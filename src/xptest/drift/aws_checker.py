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

import json
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
        message=(
            f"Resource '{resource.name}' ({resource.kind}) exists in composition "
            "but was not found in AWS."
        ),
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
        elif r.kind == "RouteTable":
            findings.extend(_check_route_table(ec2, r, spec))

    return findings


def _check_route_table(
    ec2: Any, resource: ComposedResource, spec: dict,
) -> list[DriftFinding]:
    """Check RouteTable for drift using ec2:DescribeRouteTables."""
    vpc_id = spec.get("vpcId", "")
    tags = spec.get("tags", {})

    filters: list[dict[str, Any]] = []
    if vpc_id:
        filters.append({"Name": "vpc-id", "Values": [vpc_id]})

    name_tag = tags.get("Name", "") if isinstance(tags, dict) else ""
    if name_tag:
        filters.append({"Name": "tag:Name", "Values": [name_tag]})

    if not filters:
        return []

    try:
        resp = ec2.describe_route_tables(Filters=filters)
    except Exception as exc:
        raise DriftError(f"Failed to describe RouteTables: {exc}") from exc

    rts = resp.get("RouteTables", [])
    if not rts:
        return [_resource_missing_finding(resource)]

    rt = rts[0]
    rt_id = rt.get("RouteTableId", "")

    mismatches: list[dict[str, str]] = []
    observed_vpc = rt.get("VpcId", "")
    if vpc_id and observed_vpc != vpc_id:
        mismatches.append({
            "path": "spec.forProvider.vpcId",
            "desired": vpc_id,
            "observed": observed_vpc,
        })

    return _make_findings(resource, mismatches, rt_id)


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
            s3.get_bucket_encryption(Bucket=bucket_name)
            has_encryption = True
        except s3.exceptions.ClientError as exc:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(exc):
                has_encryption = False
            else:
                raise DriftError(
                    f"Failed to get bucket encryption for {bucket_name}: {exc}"
                ) from exc

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

        # Check bucket policy (s3:GetBucketPolicy)
        desired_policy = spec.get("policy", "")
        if desired_policy:
            try:
                policy_resp = s3.get_bucket_policy(Bucket=bucket_name)
                observed_policy = policy_resp.get("Policy", "")
            except s3.exceptions.ClientError as exc:
                if "NoSuchBucketPolicy" in str(exc):
                    observed_policy = ""
                else:
                    raise DriftError(
                        f"Failed to get bucket policy for {bucket_name}: {exc}"
                    ) from exc

            desired_normalized = _normalize_json_str(desired_policy)
            observed_normalized = _normalize_json_str(observed_policy)

            if desired_normalized != observed_normalized:
                findings.append(DriftFinding(
                    layer=4,
                    rule="drift/s3-bucket-policy",
                    resource=r.name,
                    path="spec.forProvider.policy",
                    severity=Severity.CRITICAL,
                    message=(
                        f"S3 bucket '{bucket_name}' policy differs "
                        "from composition."
                    ),
                    remediation=(
                        "Update the S3 bucket policy or the composition "
                        "to match."
                    ),
                    desired=desired_normalized[:200],
                    observed=observed_normalized[:200] or "<no policy>",
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                ))

    return findings


def check_rds(session: Any, resources: list[ComposedResource]) -> list[DriftFinding]:
    """Check RDS DBInstance, DBSubnetGroup, and DBParameterGroup for drift."""
    findings: list[DriftFinding] = []
    rds = session.client("rds")

    for r in resources:
        spec = r.spec.get("forProvider", {})

        if r.kind == "DBInstance":
            findings.extend(_check_db_instance(rds, r, spec))
        elif r.kind == "DBSubnetGroup":
            findings.extend(_check_db_subnet_group(rds, r, spec))
        elif r.kind == "DBParameterGroup":
            findings.extend(_check_db_parameter_group(rds, r, spec))

    return findings


def _check_db_instance(
    rds: Any, resource: ComposedResource, spec: dict,
) -> list[DriftFinding]:
    """Check DBInstance for drift using rds:DescribeDBInstances."""
    try:
        resp = rds.describe_db_instances()
    except Exception as exc:
        raise DriftError(f"Failed to describe DB instances: {exc}") from exc

    instances = resp.get("DBInstances", [])
    matched = None
    for inst in instances:
        if (
            inst.get("Engine") == spec.get("engine")
            and inst.get("DBInstanceClass") == spec.get("dbInstanceClass")
        ):
            matched = inst
            break

    if matched is None:
        return [_resource_missing_finding(resource)]

    observed = {
        "engine": matched.get("Engine", ""),
        "dbInstanceClass": matched.get("DBInstanceClass", ""),
        "storageEncrypted": matched.get("StorageEncrypted", False),
        "publiclyAccessible": matched.get("PubliclyAccessible", False),
    }
    desired = {k: v for k, v in spec.items() if k in observed}
    mismatches = compare_fields(desired, observed)
    return _make_findings(resource, mismatches, matched.get("DBInstanceArn", ""))


def _check_db_subnet_group(
    rds: Any, resource: ComposedResource, spec: dict,
) -> list[DriftFinding]:
    """Check DBSubnetGroup for drift using rds:DescribeDBSubnetGroups."""
    group_name = spec.get("dbSubnetGroupName", resource.name)

    try:
        resp = rds.describe_db_subnet_groups(DBSubnetGroupName=group_name)
    except Exception as exc:
        err_str = str(exc)
        if "DBSubnetGroupNotFoundFault" in err_str:
            return [_resource_missing_finding(resource)]
        raise DriftError(
            f"Failed to describe DBSubnetGroup '{group_name}': {exc}"
        ) from exc

    groups = resp.get("DBSubnetGroups", [])
    if not groups:
        return [_resource_missing_finding(resource)]

    group = groups[0]
    group_arn = group.get("DBSubnetGroupArn", "")

    # Compare subnet IDs if specified
    desired_subnets = sorted(spec.get("subnetIds", []))
    observed_subnets = sorted(
        s.get("SubnetIdentifier", "") for s in group.get("Subnets", [])
    )

    mismatches: list[dict[str, str]] = []
    if desired_subnets and desired_subnets != observed_subnets:
        mismatches.append({
            "path": "spec.forProvider.subnetIds",
            "desired": str(desired_subnets),
            "observed": str(observed_subnets),
        })

    # Compare description
    desired_desc = spec.get("description", "")
    observed_desc = group.get("DBSubnetGroupDescription", "")
    if desired_desc and desired_desc != observed_desc:
        mismatches.append({
            "path": "spec.forProvider.description",
            "desired": desired_desc,
            "observed": observed_desc,
        })

    return _make_findings(resource, mismatches, group_arn)


def _check_db_parameter_group(
    rds: Any, resource: ComposedResource, spec: dict,
) -> list[DriftFinding]:
    """Check DBParameterGroup for drift using rds:DescribeDBParameterGroups."""
    group_name = spec.get("dbParameterGroupName", resource.name)

    try:
        resp = rds.describe_db_parameter_groups(DBParameterGroupName=group_name)
    except Exception as exc:
        err_str = str(exc)
        if "DBParameterGroupNotFound" in err_str:
            return [_resource_missing_finding(resource)]
        raise DriftError(
            f"Failed to describe DBParameterGroup '{group_name}': {exc}"
        ) from exc

    groups = resp.get("DBParameterGroups", [])
    if not groups:
        return [_resource_missing_finding(resource)]

    group = groups[0]
    group_arn = group.get("DBParameterGroupArn", "")

    mismatches: list[dict[str, str]] = []
    desired_family = spec.get("family", "")
    observed_family = group.get("DBParameterGroupFamily", "")
    if desired_family and desired_family != observed_family:
        mismatches.append({
            "path": "spec.forProvider.family",
            "desired": desired_family,
            "observed": observed_family,
        })

    return _make_findings(resource, mismatches, group_arn)


def check_iam(session: Any, resources: list[ComposedResource]) -> list[DriftFinding]:
    """Check IAM Role and Policy resources for drift."""
    findings: list[DriftFinding] = []
    iam = session.client("iam")

    for r in resources:
        spec = r.spec.get("forProvider", {})

        if r.kind == "Role":
            findings.extend(_check_iam_role(iam, r, spec))
        elif r.kind == "Policy":
            findings.extend(_check_iam_policy(iam, r, spec))

    return findings


def _check_iam_role(
    iam: Any, resource: ComposedResource, spec: dict,
) -> list[DriftFinding]:
    """Check IAM Role for drift using iam:GetRole + iam:ListAttachedRolePolicies."""
    role_name = spec.get("roleName", resource.name)
    findings: list[DriftFinding] = []

    try:
        resp = iam.get_role(RoleName=role_name)
    except Exception as exc:
        if "NoSuchEntity" in str(exc):
            return [_resource_missing_finding(resource)]
        raise DriftError(f"Failed to get IAM role {role_name}: {exc}") from exc

    role = resp.get("Role", {})
    role_arn = role.get("Arn", "")

    # Compare trust policy
    desired_trust = spec.get("assumeRolePolicyDocument", "")
    if desired_trust:
        observed_trust = role.get("AssumeRolePolicyDocument", "")
        desired_normalized = _normalize_json_str(
            desired_trust if isinstance(desired_trust, str)
            else json.dumps(desired_trust, sort_keys=True)
        )
        observed_normalized = _normalize_json_str(
            json.dumps(observed_trust, sort_keys=True)
            if isinstance(observed_trust, dict)
            else str(observed_trust)
        )

        if desired_normalized != observed_normalized:
            findings.append(DriftFinding(
                layer=4,
                rule="drift/iam-trust-policy",
                resource=resource.name,
                path="spec.forProvider.assumeRolePolicyDocument",
                severity=Severity.CRITICAL,
                message=(
                    f"IAM role '{role_name}' trust policy differs "
                    "from composition."
                ),
                remediation=(
                    "Update the IAM role trust policy or the "
                    "composition to match."
                ),
                desired=desired_normalized[:200],
                observed=observed_normalized[:200],
                resource_arn=role_arn,
            ))

    # iam:ListAttachedRolePolicies — check managed policy attachments
    try:
        attached_resp = iam.list_attached_role_policies(RoleName=role_name)
        attached_arns = sorted(
            p["PolicyArn"]
            for p in attached_resp.get("AttachedPolicies", [])
        )
    except Exception:
        attached_arns = []

    desired_attached = sorted(spec.get("managedPolicyArns", []))
    if desired_attached and desired_attached != attached_arns:
        findings.append(DriftFinding(
            layer=4,
            rule="drift/iam-attached-policies",
            resource=resource.name,
            path="spec.forProvider.managedPolicyArns",
            severity=Severity.CRITICAL,
            message=(
                f"IAM role '{role_name}' attached managed policies "
                "differ from composition."
            ),
            remediation=(
                "Attach or detach managed policies to match the "
                "composition declaration."
            ),
            desired=str(desired_attached)[:200],
            observed=str(attached_arns)[:200],
            resource_arn=role_arn,
        ))

    return findings


def _check_iam_policy(
    iam: Any, resource: ComposedResource, spec: dict,
) -> list[DriftFinding]:
    """Check IAM Policy inline document using iam:GetRolePolicy (for inline)
    or by comparing the policy document directly."""
    # Crossplane IAM Policy resources carry the policy JSON in spec.forProvider.policy
    desired_doc = spec.get("policy", "")
    if not desired_doc:
        return []

    # For managed policies, compare via the policy ARN
    policy_name = spec.get("name", resource.name)
    role_name = spec.get("roleName", "")

    if not role_name:
        # Without a role name we cannot call GetRolePolicy; skip
        return []

    try:
        resp = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    except Exception as exc:
        if "NoSuchEntity" in str(exc):
            return [_resource_missing_finding(resource)]
        raise DriftError(
            f"Failed to get role policy '{policy_name}' for role "
            f"'{role_name}': {exc}"
        ) from exc

    observed_doc = resp.get("PolicyDocument", "")
    desired_normalized = _normalize_json_str(desired_doc)
    observed_normalized = _normalize_json_str(
        json.dumps(observed_doc, sort_keys=True)
        if isinstance(observed_doc, dict)
        else str(observed_doc)
    )

    if desired_normalized != observed_normalized:
        return [DriftFinding(
            layer=4,
            rule="drift/iam-role-policy",
            resource=resource.name,
            path="spec.forProvider.policy",
            severity=Severity.CRITICAL,
            message=(
                f"Inline policy '{policy_name}' on role '{role_name}' "
                "differs from composition."
            ),
            remediation="Update the inline policy or the composition to match.",
            desired=desired_normalized[:200],
            observed=observed_normalized[:200],
            resource_arn="",
        )]

    return []


# ────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────


def _normalize_json_str(value: str | Any) -> str:
    """Normalize a JSON string for comparison by re-serializing with sorted keys."""
    if not isinstance(value, str):
        value = str(value)
    try:
        return json.dumps(json.loads(value), sort_keys=True)
    except (json.JSONDecodeError, TypeError, ValueError):
        return value
