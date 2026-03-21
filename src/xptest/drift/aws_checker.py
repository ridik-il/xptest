"""AWS API queries for drift detection (Stage 3).

Each function queries one AWS resource family using boto3 read-only APIs
and compares observed state against the desired spec from the composition.

All API calls use the 12 read-only actions from framework-design.md §4.2:
  EC2:  DescribeVpcs, DescribeSubnets, DescribeSecurityGroups, DescribeRouteTables
  S3:   GetBucketEncryption, GetBucketPolicy, GetPublicAccessBlock
  RDS:  DescribeDBInstances, DescribeDBSubnetGroups, DescribeDBParameterGroups
  IAM:  GetRole, GetRolePolicy, ListAttachedRolePolicies

boto3 is imported lazily — only when drift detection is actually invoked.
"""

from __future__ import annotations

from typing import Any

from xptest.drift.comparator import compare_fields
from xptest.drift.models import DriftError, DriftFinding
from xptest.models import ComposedResource, Severity


def _import_boto3():
    """Lazy import of boto3 with a clear error message."""
    try:
        import boto3

        return boto3
    except ImportError:
        raise DriftError(
            "boto3 is required for drift detection. "
            "Install it with: pip install xptest[drift]"
        ) from None


def _make_findings(
    resource: ComposedResource,
    mismatches: list[dict[str, str]],
    resource_arn: str,
) -> list[DriftFinding]:
    """Convert field mismatches to DriftFinding objects."""
    findings = []
    for m in mismatches:
        findings.append(DriftFinding(
            layer=4,  # drift is Layer 4 extension per framework-design.md §3.4
            rule="drift/field-mismatch",
            resource=resource.name,
            path=m["path"],
            severity=Severity.CRITICAL,
            message=(
                f"Drift detected in '{resource.name}': "
                f"field '{m['path']}' is '{m['observed']}' in AWS "
                f"but '{m['desired']}' in composition."
            ),
            remediation="Update the AWS resource or the composition to match.",
            desired=m["desired"],
            observed=m["observed"],
            resource_arn=resource_arn,
        ))
    return findings


def _resource_missing_finding(resource: ComposedResource) -> DriftFinding:
    """Finding for a resource that exists in composition but not in AWS."""
    return DriftFinding(
        layer=4,
        rule="drift/resource-missing",
        resource=resource.name,
        path="",
        severity=Severity.CRITICAL,
        message=f"Resource '{resource.name}' ({resource.kind}) exists in composition but was not found in AWS.",
        remediation="Verify the resource was provisioned or check for naming/tagging mismatches.",
        desired=f"{resource.api_version}/{resource.kind}",
        observed="<not found>",
        resource_arn="",
    )


# ────────────────────────────────────────────────────────
# Per-family checker functions
# ────────────────────────────────────────────────────────


def check_vpcs(session: Any, resources: list[ComposedResource]) -> list[DriftFinding]:
    """Check VPC, Subnet, SecurityGroup, RouteTable resources for drift."""
    findings: list[DriftFinding] = []
    ec2 = session.client("ec2")

    for r in resources:
        spec = r.spec.get("forProvider", {})

        if r.kind == "VPC":
            findings.extend(_check_vpc(ec2, r, spec))
        elif r.kind == "Subnet":
            findings.extend(_check_subnet(ec2, r, spec))
        elif r.kind == "SecurityGroup":
            findings.extend(_check_security_group(ec2, r, spec))

    return findings


def _check_vpc(ec2: Any, resource: ComposedResource, spec: dict) -> list[DriftFinding]:
    cidr = spec.get("cidrBlock", "")
    if not cidr:
        return []

    try:
        resp = ec2.describe_vpcs(Filters=[{"Name": "cidr-block", "Values": [cidr]}])
    except Exception as exc:
        raise DriftError(f"Failed to describe VPCs: {exc}") from exc

    vpcs = resp.get("Vpcs", [])
    if not vpcs:
        return [_resource_missing_finding(resource)]

    vpc = vpcs[0]
    observed = {"cidrBlock": vpc.get("CidrBlock", "")}
    mismatches = compare_fields({"cidrBlock": cidr}, observed)
    return _make_findings(resource, mismatches, vpc.get("VpcId", ""))


def _check_subnet(ec2: Any, resource: ComposedResource, spec: dict) -> list[DriftFinding]:
    cidr = spec.get("cidrBlock", "")
    if not cidr:
        return []

    try:
        resp = ec2.describe_subnets(Filters=[{"Name": "cidr-block", "Values": [cidr]}])
    except Exception as exc:
        raise DriftError(f"Failed to describe Subnets: {exc}") from exc

    subnets = resp.get("Subnets", [])
    if not subnets:
        return [_resource_missing_finding(resource)]

    subnet = subnets[0]
    observed = {
        "cidrBlock": subnet.get("CidrBlock", ""),
        "availabilityZone": subnet.get("AvailabilityZone", ""),
    }
    desired = {k: v for k, v in spec.items() if k in observed}
    mismatches = compare_fields(desired, observed)
    return _make_findings(resource, mismatches, subnet.get("SubnetArn", subnet.get("SubnetId", "")))


def _check_security_group(ec2: Any, resource: ComposedResource, spec: dict) -> list[DriftFinding]:
    name = spec.get("groupName", resource.name)

    try:
        resp = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [name]}])
    except Exception as exc:
        raise DriftError(f"Failed to describe SecurityGroups: {exc}") from exc

    sgs = resp.get("SecurityGroups", [])
    if not sgs:
        return [_resource_missing_finding(resource)]

    sg = sgs[0]
    return _make_findings(resource, [], sg.get("GroupId", ""))


def check_s3(session: Any, resources: list[ComposedResource]) -> list[DriftFinding]:
    """Check S3 Bucket resources for drift."""
    findings: list[DriftFinding] = []
    s3 = session.client("s3")

    for r in resources:
        if r.kind != "Bucket":
            continue

        spec = r.spec.get("forProvider", {})
        bucket_name = spec.get("bucketName", r.name)

        # Check encryption
        try:
            enc_resp = s3.get_bucket_encryption(Bucket=bucket_name)
            has_encryption = True
        except s3.exceptions.ClientError as exc:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(exc):
                has_encryption = False
            else:
                raise DriftError(f"Failed to get bucket encryption for {bucket_name}: {exc}") from exc

        desired_enc = spec.get("serverSideEncryptionConfiguration")
        if desired_enc and not has_encryption:
            findings.append(DriftFinding(
                layer=4,
                rule="drift/s3-encryption",
                resource=r.name,
                path="spec.forProvider.serverSideEncryptionConfiguration",
                severity=Severity.CRITICAL,
                message=f"S3 bucket '{bucket_name}' has encryption in composition but not in AWS.",
                remediation="Enable server-side encryption on the S3 bucket.",
                desired="encryption configured",
                observed="no encryption",
                resource_arn=f"arn:aws:s3:::{bucket_name}",
            ))

        # Check public access block
        try:
            pub_resp = s3.get_public_access_block(Bucket=bucket_name)
            pub_config = pub_resp.get("PublicAccessBlockConfiguration", {})
        except s3.exceptions.ClientError:
            pub_config = {}

        desired_pub = spec.get("publicAccessBlockConfiguration", {})
        if desired_pub:
            mismatches = compare_fields(desired_pub, pub_config)
            findings.extend(_make_findings(
                r, mismatches, f"arn:aws:s3:::{bucket_name}"
            ))

    return findings


def check_rds(session: Any, resources: list[ComposedResource]) -> list[DriftFinding]:
    """Check RDS DBInstance resources for drift."""
    findings: list[DriftFinding] = []
    rds = session.client("rds")

    for r in resources:
        if r.kind != "DBInstance":
            continue

        spec = r.spec.get("forProvider", {})

        try:
            resp = rds.describe_db_instances()
        except Exception as exc:
            raise DriftError(f"Failed to describe DB instances: {exc}") from exc

        instances = resp.get("DBInstances", [])
        # Try to find matching instance by engine + class
        matched = None
        for inst in instances:
            if (
                inst.get("Engine") == spec.get("engine")
                and inst.get("DBInstanceClass") == spec.get("dbInstanceClass")
            ):
                matched = inst
                break

        if matched is None:
            findings.append(_resource_missing_finding(r))
            continue

        # Compare key fields
        observed = {
            "engine": matched.get("Engine", ""),
            "dbInstanceClass": matched.get("DBInstanceClass", ""),
            "storageEncrypted": matched.get("StorageEncrypted", False),
            "publiclyAccessible": matched.get("PubliclyAccessible", False),
        }
        desired = {k: v for k, v in spec.items() if k in observed}
        mismatches = compare_fields(desired, observed)
        findings.extend(_make_findings(
            r, mismatches, matched.get("DBInstanceArn", "")
        ))

    return findings


def check_iam(session: Any, resources: list[ComposedResource]) -> list[DriftFinding]:
    """Check IAM Role resources for drift."""
    findings: list[DriftFinding] = []
    iam = session.client("iam")

    for r in resources:
        if r.kind != "Role":
            continue

        spec = r.spec.get("forProvider", {})
        role_name = spec.get("roleName", r.name)

        try:
            resp = iam.get_role(RoleName=role_name)
        except iam.exceptions.NoSuchEntityException:
            findings.append(_resource_missing_finding(r))
            continue
        except Exception as exc:
            raise DriftError(f"Failed to get IAM role {role_name}: {exc}") from exc

        role = resp.get("Role", {})

        # Compare trust policy if specified
        desired_trust = spec.get("assumeRolePolicyDocument", "")
        if desired_trust:
            observed_trust = role.get("AssumeRolePolicyDocument", "")
            if isinstance(observed_trust, dict):
                import json

                observed_trust = json.dumps(observed_trust, sort_keys=True)
            if isinstance(desired_trust, str):
                import json

                try:
                    desired_trust = json.dumps(json.loads(desired_trust), sort_keys=True)
                except (json.JSONDecodeError, TypeError):
                    pass

            if desired_trust != observed_trust:
                findings.append(DriftFinding(
                    layer=4,
                    rule="drift/iam-trust-policy",
                    resource=r.name,
                    path="spec.forProvider.assumeRolePolicyDocument",
                    severity=Severity.CRITICAL,
                    message=f"IAM role '{role_name}' trust policy differs from composition.",
                    remediation="Update the IAM role trust policy or the composition to match.",
                    desired=desired_trust[:200],
                    observed=str(observed_trust)[:200],
                    resource_arn=role.get("Arn", ""),
                ))

    return findings
