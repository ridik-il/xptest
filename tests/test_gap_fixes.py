"""Tests for gap-fill implementations.

Covers:
  - L1-06 EnvironmentConfig fixture presence check
  - L3-01 OPA version enforcement
  - Drift: RouteTable, S3 BucketPolicy, DBSubnetGroup, DBParameterGroup,
           IAM attached policies, IAM inline policy
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

from xptest.layer1 import static as layer1
from xptest.loader import load
from xptest.models import (
    ComposedResource,
    CompositionMode,
    CompositionObject,
    Severity,
)

_HERE = Path(__file__).parent
FIXTURES_DIR = _HERE.parent / "fixtures"
XRD_PATH = str(FIXTURES_DIR / "xrd.yaml")


def _make_resource(name: str, kind: str, spec: dict | None = None) -> ComposedResource:
    return ComposedResource(
        name=name,
        api_version="test/v1",
        kind=kind,
        spec=spec or {},
    )


def _make_obj(*resources: ComposedResource, **kwargs) -> CompositionObject:
    return CompositionObject(
        composition_name="test",
        composition_path="test.yaml",
        xrd_name="test-xrd",
        xrd_path="xrd.yaml",
        mode=CompositionMode.RESOURCES,
        resources=list(resources),
        **kwargs,
    )


# ────────────────────────────────────────────────────────
# L1-06 — EnvironmentConfig fixture presence check
# ────────────────────────────────────────────────────────


class TestEnvironmentConfigPresence:
    def test_no_env_patches_no_finding(self):
        """Composition without FromEnvironmentFieldPath → no L1-06 finding."""
        resource = ComposedResource(
            name="vpc",
            api_version="ec2/v1",
            kind="VPC",
            spec={},
            patches=[
                {"type": "FromCompositeFieldPath", "fromFieldPath": "spec.region"},
            ],
        )
        obj = _make_obj(resource)
        findings = layer1.run(obj)
        l106 = [f for f in findings if f.rule == "L1-06/environment-config-missing"]
        assert l106 == []

    def test_env_patches_without_fixtures_warns(self):
        """FromEnvironmentFieldPath present but no fixture → WARNING."""
        resource = ComposedResource(
            name="vpc",
            api_version="ec2/v1",
            kind="VPC",
            spec={},
            patches=[
                {
                    "type": "FromEnvironmentFieldPath",
                    "fromFieldPath": "data.accountId",
                    "toFieldPath": "spec.forProvider.tags.AccountId",
                },
            ],
        )
        obj = _make_obj(resource, environment_config_paths=[])
        findings = layer1.run(obj)
        l106 = [f for f in findings if f.rule == "L1-06/environment-config-missing"]
        assert len(l106) == 1
        assert l106[0].severity == Severity.WARNING

    def test_env_patches_with_fixtures_no_finding(self):
        """FromEnvironmentFieldPath present with fixture supplied → no finding."""
        resource = ComposedResource(
            name="vpc",
            api_version="ec2/v1",
            kind="VPC",
            spec={},
            patches=[
                {
                    "type": "FromEnvironmentFieldPath",
                    "fromFieldPath": "data.accountId",
                    "toFieldPath": "spec.forProvider.tags.AccountId",
                },
            ],
        )
        obj = _make_obj(
            resource,
            environment_config_paths=["/path/to/envconfig.yaml"],
        )
        findings = layer1.run(obj)
        l106 = [f for f in findings if f.rule == "L1-06/environment-config-missing"]
        assert l106 == []

    def test_env_check_in_full_composition(self, tmp_path):
        """Integration: load a composition with env patches, verify L1-06 fires."""
        xrd = tmp_path / "xrd.yaml"
        xrd.write_text(Path(XRD_PATH).read_text())

        comp = tmp_path / "env_patch.yaml"
        comp.write_text(
            textwrap.dedent("""
            apiVersion: apiextensions.crossplane.io/v1
            kind: Composition
            metadata:
              name: env-patch-test
            spec:
              compositeTypeRef:
                apiVersion: aws.example.org/v1alpha1
                kind: XVPCNetwork
              mode: Resources
              resources:
                - name: main-vpc
                  base:
                    apiVersion: ec2.aws.crossplane.io/v1beta1
                    kind: VPC
                    spec:
                      forProvider:
                        cidrBlock: "10.0.0.0/16"
                        region: "eu-west-1"
                  patches:
                    - type: FromEnvironmentFieldPath
                      fromFieldPath: data.region
                      toFieldPath: spec.forProvider.region
            """)
        )

        obj = load(str(comp), str(xrd))
        findings = layer1.run(obj)
        l106 = [f for f in findings if f.rule == "L1-06/environment-config-missing"]
        assert len(l106) == 1


# ────────────────────────────────────────────────────────
# L3-01 — OPA version enforcement
# ────────────────────────────────────────────────────────


class TestOpaVersionCheck:
    def test_version_match_no_finding(self):
        from xptest.config import Config
        from xptest.layer3.policy import _check_opa_version

        cfg = Config(opa_expected_version="0.60.0")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="Version: 0.60.0\nBuild Commit: abc123\n",
                returncode=0,
            )
            result = _check_opa_version(cfg)
        assert result is None

    def test_version_mismatch_warns(self):
        from xptest.config import Config
        from xptest.layer3.policy import _check_opa_version

        cfg = Config(opa_expected_version="0.60.0")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="Version: 0.55.0\nBuild Commit: def456\n",
                returncode=0,
            )
            result = _check_opa_version(cfg)
        assert result is not None
        assert result.rule == "L3-01/opa-version-mismatch"
        assert result.severity == Severity.WARNING
        assert "0.55.0" in result.message
        assert "0.60.0" in result.message

    def test_opa_not_found_no_finding(self):
        from xptest.config import Config
        from xptest.layer3.policy import _check_opa_version

        cfg = Config(opa_expected_version="0.60.0")
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = _check_opa_version(cfg)
        assert result is None

    def test_no_expected_version_skips(self):
        """When opa_expected_version is empty, no check runs."""
        from xptest.config import Config
        from xptest.layer3.policy import run

        cfg = Config(opa_expected_version="", rules_path="")
        obj = _make_obj()
        findings = run(obj, cfg)
        assert findings == []


# ────────────────────────────────────────────────────────
# Drift: RouteTable checker
# ────────────────────────────────────────────────────────


class TestRouteTableChecker:
    def test_route_table_no_drift(self):
        from xptest.drift.aws_checker import check_vpcs

        session = MagicMock()
        ec2 = session.client.return_value
        ec2.describe_route_tables.return_value = {
            "RouteTables": [
                {
                    "RouteTableId": "rtb-123",
                    "VpcId": "vpc-abc",
                }
            ]
        }

        resource = _make_resource("main-rt", "RouteTable", {"forProvider": {"vpcId": "vpc-abc"}})
        findings = check_vpcs(session, [resource])
        assert findings == []

    def test_route_table_vpc_drift(self):
        from xptest.drift.aws_checker import check_vpcs

        session = MagicMock()
        ec2 = session.client.return_value
        ec2.describe_route_tables.return_value = {
            "RouteTables": [
                {
                    "RouteTableId": "rtb-123",
                    "VpcId": "vpc-wrong",
                }
            ]
        }

        resource = _make_resource("main-rt", "RouteTable", {"forProvider": {"vpcId": "vpc-abc"}})
        findings = check_vpcs(session, [resource])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].desired == "vpc-abc"
        assert findings[0].observed == "vpc-wrong"

    def test_route_table_missing(self):
        from xptest.drift.aws_checker import check_vpcs

        session = MagicMock()
        ec2 = session.client.return_value
        ec2.describe_route_tables.return_value = {"RouteTables": []}

        resource = _make_resource("main-rt", "RouteTable", {"forProvider": {"vpcId": "vpc-abc"}})
        findings = check_vpcs(session, [resource])
        assert len(findings) == 1
        assert findings[0].rule == "drift/resource-missing"

    def test_route_table_no_filter_skips(self):
        from xptest.drift.aws_checker import check_vpcs

        session = MagicMock()
        ec2 = session.client.return_value

        resource = _make_resource("main-rt", "RouteTable", {"forProvider": {}})
        findings = check_vpcs(session, [resource])
        assert findings == []
        ec2.describe_route_tables.assert_not_called()


# ────────────────────────────────────────────────────────
# Drift: S3 BucketPolicy checker
# ────────────────────────────────────────────────────────


class TestS3BucketPolicyChecker:
    def test_bucket_policy_no_drift(self):
        from xptest.drift.aws_checker import check_s3

        session = MagicMock()
        s3 = session.client.return_value
        error_cls = type("ClientError", (Exception,), {})
        s3.exceptions.ClientError = error_cls
        s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {}}
        s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}

        policy = json.dumps({"Version": "2012-10-17", "Statement": []})
        s3.get_bucket_policy.return_value = {"Policy": policy}

        resource = _make_resource(
            "data-bucket",
            "Bucket",
            {
                "forProvider": {
                    "bucketName": "test-bucket",
                    "policy": policy,
                }
            },
        )
        findings = check_s3(session, [resource])
        policy_findings = [f for f in findings if f.rule == "drift/s3-bucket-policy"]
        assert policy_findings == []

    def test_bucket_policy_drift(self):
        from xptest.drift.aws_checker import check_s3

        session = MagicMock()
        s3 = session.client.return_value
        error_cls = type("ClientError", (Exception,), {})
        s3.exceptions.ClientError = error_cls
        s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {}}
        s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}

        desired_policy = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny"}]})
        observed_policy = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]})
        s3.get_bucket_policy.return_value = {"Policy": observed_policy}

        resource = _make_resource(
            "data-bucket",
            "Bucket",
            {
                "forProvider": {
                    "bucketName": "test-bucket",
                    "policy": desired_policy,
                }
            },
        )
        findings = check_s3(session, [resource])
        policy_findings = [f for f in findings if f.rule == "drift/s3-bucket-policy"]
        assert len(policy_findings) == 1
        assert policy_findings[0].severity == Severity.CRITICAL

    def test_bucket_policy_missing_in_aws(self):
        from xptest.drift.aws_checker import check_s3

        session = MagicMock()
        s3 = session.client.return_value
        error_cls = type("ClientError", (Exception,), {})
        s3.exceptions.ClientError = error_cls
        s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {}}
        s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
        s3.get_bucket_policy.side_effect = error_cls("NoSuchBucketPolicy")

        desired_policy = json.dumps({"Version": "2012-10-17", "Statement": []})
        resource = _make_resource(
            "data-bucket",
            "Bucket",
            {
                "forProvider": {
                    "bucketName": "test-bucket",
                    "policy": desired_policy,
                }
            },
        )
        findings = check_s3(session, [resource])
        policy_findings = [f for f in findings if f.rule == "drift/s3-bucket-policy"]
        assert len(policy_findings) == 1


# ────────────────────────────────────────────────────────
# Drift: DBSubnetGroup checker
# ────────────────────────────────────────────────────────


class TestDBSubnetGroupChecker:
    def test_db_subnet_group_no_drift(self):
        from xptest.drift.aws_checker import check_rds

        session = MagicMock()
        rds = session.client.return_value
        rds.describe_db_subnet_groups.return_value = {
            "DBSubnetGroups": [
                {
                    "DBSubnetGroupArn": "arn:rds:subnet-group",
                    "DBSubnetGroupDescription": "test group",
                    "Subnets": [
                        {"SubnetIdentifier": "subnet-1"},
                        {"SubnetIdentifier": "subnet-2"},
                    ],
                }
            ]
        }

        resource = _make_resource(
            "db-subnet-grp",
            "DBSubnetGroup",
            {
                "forProvider": {
                    "dbSubnetGroupName": "test-group",
                    "description": "test group",
                    "subnetIds": ["subnet-1", "subnet-2"],
                }
            },
        )
        findings = check_rds(session, [resource])
        assert findings == []

    def test_db_subnet_group_subnet_drift(self):
        from xptest.drift.aws_checker import check_rds

        session = MagicMock()
        rds = session.client.return_value
        rds.describe_db_subnet_groups.return_value = {
            "DBSubnetGroups": [
                {
                    "DBSubnetGroupArn": "arn:rds:subnet-group",
                    "DBSubnetGroupDescription": "test group",
                    "Subnets": [
                        {"SubnetIdentifier": "subnet-1"},
                        {"SubnetIdentifier": "subnet-3"},
                    ],
                }
            ]
        }

        resource = _make_resource(
            "db-subnet-grp",
            "DBSubnetGroup",
            {
                "forProvider": {
                    "dbSubnetGroupName": "test-group",
                    "subnetIds": ["subnet-1", "subnet-2"],
                }
            },
        )
        findings = check_rds(session, [resource])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_db_subnet_group_missing(self):
        from xptest.drift.aws_checker import check_rds

        session = MagicMock()
        rds = session.client.return_value
        rds.describe_db_subnet_groups.side_effect = Exception(
            "DBSubnetGroupNotFoundFault: not found"
        )

        resource = _make_resource(
            "db-subnet-grp",
            "DBSubnetGroup",
            {"forProvider": {"dbSubnetGroupName": "missing-group"}},
        )
        findings = check_rds(session, [resource])
        assert len(findings) == 1
        assert findings[0].rule == "drift/resource-missing"


# ────────────────────────────────────────────────────────
# Drift: DBParameterGroup checker
# ────────────────────────────────────────────────────────


class TestDBParameterGroupChecker:
    def test_db_parameter_group_no_drift(self):
        from xptest.drift.aws_checker import check_rds

        session = MagicMock()
        rds = session.client.return_value
        rds.describe_db_parameter_groups.return_value = {
            "DBParameterGroups": [
                {
                    "DBParameterGroupArn": "arn:rds:pg",
                    "DBParameterGroupFamily": "postgres14",
                }
            ]
        }

        resource = _make_resource(
            "db-params",
            "DBParameterGroup",
            {
                "forProvider": {
                    "dbParameterGroupName": "test-pg",
                    "family": "postgres14",
                }
            },
        )
        findings = check_rds(session, [resource])
        assert findings == []

    def test_db_parameter_group_family_drift(self):
        from xptest.drift.aws_checker import check_rds

        session = MagicMock()
        rds = session.client.return_value
        rds.describe_db_parameter_groups.return_value = {
            "DBParameterGroups": [
                {
                    "DBParameterGroupArn": "arn:rds:pg",
                    "DBParameterGroupFamily": "postgres13",
                }
            ]
        }

        resource = _make_resource(
            "db-params",
            "DBParameterGroup",
            {
                "forProvider": {
                    "dbParameterGroupName": "test-pg",
                    "family": "postgres14",
                }
            },
        )
        findings = check_rds(session, [resource])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_db_parameter_group_missing(self):
        from xptest.drift.aws_checker import check_rds

        session = MagicMock()
        rds = session.client.return_value
        rds.describe_db_parameter_groups.side_effect = Exception(
            "DBParameterGroupNotFound: not found"
        )

        resource = _make_resource(
            "db-params", "DBParameterGroup", {"forProvider": {"dbParameterGroupName": "missing-pg"}}
        )
        findings = check_rds(session, [resource])
        assert len(findings) == 1
        assert findings[0].rule == "drift/resource-missing"


# ────────────────────────────────────────────────────────
# Drift: IAM attached policies checker
# ────────────────────────────────────────────────────────


class TestIamAttachedPoliciesChecker:
    def test_attached_policies_no_drift(self):
        from xptest.drift.aws_checker import check_iam

        session = MagicMock()
        iam = session.client.return_value
        iam.exceptions.NoSuchEntityException = type("NoSuchEntityException", (Exception,), {})
        iam.get_role.return_value = {
            "Role": {
                "Arn": "arn:aws:iam::123:role/app",
                "AssumeRolePolicyDocument": {},
            }
        }
        iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
            ]
        }

        resource = _make_resource(
            "app-role",
            "Role",
            {
                "forProvider": {
                    "roleName": "app",
                    "managedPolicyArns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
                }
            },
        )
        findings = check_iam(session, [resource])
        attached = [f for f in findings if f.rule == "drift/iam-attached-policies"]
        assert attached == []

    def test_attached_policies_drift(self):
        from xptest.drift.aws_checker import check_iam

        session = MagicMock()
        iam = session.client.return_value
        iam.exceptions.NoSuchEntityException = type("NoSuchEntityException", (Exception,), {})
        iam.get_role.return_value = {
            "Role": {
                "Arn": "arn:aws:iam::123:role/app",
                "AssumeRolePolicyDocument": {},
            }
        }
        iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyArn": "arn:aws:iam::aws:policy/AdminAccess"},
            ]
        }

        resource = _make_resource(
            "app-role",
            "Role",
            {
                "forProvider": {
                    "roleName": "app",
                    "managedPolicyArns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
                }
            },
        )
        findings = check_iam(session, [resource])
        attached = [f for f in findings if f.rule == "drift/iam-attached-policies"]
        assert len(attached) == 1
        assert attached[0].severity == Severity.CRITICAL


# ────────────────────────────────────────────────────────
# Drift: IAM inline policy checker (GetRolePolicy)
# ────────────────────────────────────────────────────────


class TestIamInlinePolicyChecker:
    def test_inline_policy_no_drift(self):
        from xptest.drift.aws_checker import check_iam

        session = MagicMock()
        iam = session.client.return_value
        iam.exceptions.NoSuchEntityException = type("NoSuchEntityException", (Exception,), {})

        policy_doc = {"Version": "2012-10-17", "Statement": []}
        iam.get_role_policy.return_value = {
            "PolicyDocument": policy_doc,
        }

        resource = _make_resource(
            "app-policy",
            "Policy",
            {
                "forProvider": {
                    "name": "app-inline",
                    "roleName": "app-role",
                    "policy": json.dumps(policy_doc),
                }
            },
        )
        findings = check_iam(session, [resource])
        inline = [f for f in findings if f.rule == "drift/iam-role-policy"]
        assert inline == []

    def test_inline_policy_drift(self):
        from xptest.drift.aws_checker import check_iam

        session = MagicMock()
        iam = session.client.return_value
        iam.exceptions.NoSuchEntityException = type("NoSuchEntityException", (Exception,), {})

        desired = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny"}]}
        observed = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]}
        iam.get_role_policy.return_value = {"PolicyDocument": observed}

        resource = _make_resource(
            "app-policy",
            "Policy",
            {
                "forProvider": {
                    "name": "app-inline",
                    "roleName": "app-role",
                    "policy": json.dumps(desired),
                }
            },
        )
        findings = check_iam(session, [resource])
        inline = [f for f in findings if f.rule == "drift/iam-role-policy"]
        assert len(inline) == 1
        assert inline[0].severity == Severity.CRITICAL

    def test_inline_policy_missing(self):
        from xptest.drift.aws_checker import check_iam

        session = MagicMock()
        iam = session.client.return_value
        iam.exceptions.NoSuchEntityException = type("NoSuchEntityException", (Exception,), {})
        iam.get_role_policy.side_effect = Exception("NoSuchEntity: not found")

        resource = _make_resource(
            "app-policy",
            "Policy",
            {
                "forProvider": {
                    "name": "app-inline",
                    "roleName": "app-role",
                    "policy": '{"Statement": []}',
                }
            },
        )
        findings = check_iam(session, [resource])
        missing = [f for f in findings if f.rule == "drift/resource-missing"]
        assert len(missing) == 1
