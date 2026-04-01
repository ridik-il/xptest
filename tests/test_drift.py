"""Tests for drift detection module.

All tests use mocked boto3 — no real AWS API calls.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from xptest.config import Config
from xptest.drift.comparator import compare_fields
from xptest.drift.models import DriftError
from xptest.models import ComposedResource, CompositionMode, CompositionObject, Severity


def _make_resource(name: str, kind: str, spec: dict | None = None) -> ComposedResource:
    return ComposedResource(
        name=name,
        api_version="test/v1",
        kind=kind,
        spec=spec or {},
    )


def _make_obj(*resources: ComposedResource) -> CompositionObject:
    return CompositionObject(
        composition_name="test",
        composition_path="test.yaml",
        xrd_name="test-xrd",
        xrd_path="xrd.yaml",
        mode=CompositionMode.RESOURCES,
        resources=list(resources),
    )


def _config(**overrides) -> Config:
    return Config(**overrides)


# ────────────────────────────────────────────────────────
# Comparator tests
# ────────────────────────────────────────────────────────


class TestComparator:
    def test_matching_fields_no_mismatches(self):
        desired = {"cidrBlock": "10.0.0.0/16", "region": "eu-west-1"}
        observed = {"cidrBlock": "10.0.0.0/16", "region": "eu-west-1"}
        assert compare_fields(desired, observed) == []

    def test_field_value_mismatch(self):
        desired = {"cidrBlock": "10.0.0.0/16"}
        observed = {"cidrBlock": "10.0.1.0/24"}
        mismatches = compare_fields(desired, observed)
        assert len(mismatches) == 1
        assert mismatches[0]["path"] == "cidrBlock"
        assert mismatches[0]["desired"] == "10.0.0.0/16"
        assert mismatches[0]["observed"] == "10.0.1.0/24"

    def test_missing_observed_field(self):
        desired = {"storageEncrypted": True}
        observed = {}
        mismatches = compare_fields(desired, observed)
        assert len(mismatches) == 1
        assert mismatches[0]["observed"] == "<missing>"

    def test_nested_field_mismatch(self):
        desired = {"config": {"enabled": True, "timeout": 30}}
        observed = {"config": {"enabled": False, "timeout": 30}}
        mismatches = compare_fields(desired, observed)
        assert len(mismatches) == 1
        assert mismatches[0]["path"] == "config/enabled"

    def test_ignores_aws_managed_fields(self):
        desired = {"cidrBlock": "10.0.0.0/16", "arn": "should-be-ignored"}
        observed = {"cidrBlock": "10.0.0.0/16", "arn": "different-value"}
        assert compare_fields(desired, observed) == []

    def test_boolean_string_normalization(self):
        desired = {"publiclyAccessible": False}
        observed = {"publiclyAccessible": "false"}
        assert compare_fields(desired, observed) == []

    def test_list_comparison(self):
        desired = {"tags": [{"Key": "Env", "Value": "prod"}]}
        observed = {"tags": [{"Key": "Env", "Value": "dev"}]}
        mismatches = compare_fields(desired, observed)
        assert len(mismatches) == 1
        assert "Value" in mismatches[0]["path"]

    def test_extra_observed_fields_ignored(self):
        desired = {"region": "eu-west-1"}
        observed = {"region": "eu-west-1", "vpcId": "vpc-123", "state": "available"}
        assert compare_fields(desired, observed) == []


# ────────────────────────────────────────────────────────
# AWS checker tests (mocked boto3)
# ────────────────────────────────────────────────────────


class TestVpcChecker:
    def test_vpc_no_drift(self):
        from xptest.drift.aws_checker import check_vpcs

        session = MagicMock()
        ec2 = session.client.return_value
        ec2.describe_vpcs.return_value = {
            "Vpcs": [{"CidrBlock": "10.0.0.0/16", "VpcId": "vpc-123"}]
        }

        resource = _make_resource("main-vpc", "VPC", {"forProvider": {"cidrBlock": "10.0.0.0/16"}})
        findings = check_vpcs(session, [resource])
        assert findings == []

    def test_vpc_cidr_drift(self):
        from xptest.drift.aws_checker import check_vpcs

        session = MagicMock()
        ec2 = session.client.return_value
        ec2.describe_vpcs.return_value = {
            "Vpcs": [{"CidrBlock": "10.0.1.0/24", "VpcId": "vpc-123"}]
        }

        resource = _make_resource("main-vpc", "VPC", {"forProvider": {"cidrBlock": "10.0.0.0/16"}})
        findings = check_vpcs(session, [resource])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].desired == "10.0.0.0/16"
        assert findings[0].observed == "10.0.1.0/24"

    def test_vpc_missing(self):
        from xptest.drift.aws_checker import check_vpcs

        session = MagicMock()
        ec2 = session.client.return_value
        ec2.describe_vpcs.return_value = {"Vpcs": []}

        resource = _make_resource("main-vpc", "VPC", {"forProvider": {"cidrBlock": "10.0.0.0/16"}})
        findings = check_vpcs(session, [resource])
        assert len(findings) == 1
        assert findings[0].rule == "drift/resource-missing"


class TestRdsChecker:
    def test_rds_no_drift(self):
        from xptest.drift.aws_checker import check_rds

        session = MagicMock()
        rds = session.client.return_value
        rds.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "Engine": "postgres",
                    "DBInstanceClass": "db.t3.micro",
                    "StorageEncrypted": True,
                    "PubliclyAccessible": False,
                    "DBInstanceArn": "arn:aws:rds:eu-west-1:123:db:test",
                }
            ]
        }

        resource = _make_resource(
            "main-db",
            "DBInstance",
            {
                "forProvider": {
                    "engine": "postgres",
                    "dbInstanceClass": "db.t3.micro",
                    "storageEncrypted": True,
                    "publiclyAccessible": False,
                }
            },
        )
        findings = check_rds(session, [resource])
        assert findings == []

    def test_rds_publicly_accessible_drift(self):
        from xptest.drift.aws_checker import check_rds

        session = MagicMock()
        rds = session.client.return_value
        rds.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "Engine": "postgres",
                    "DBInstanceClass": "db.t3.micro",
                    "StorageEncrypted": True,
                    "PubliclyAccessible": True,
                    "DBInstanceArn": "arn:aws:rds:eu-west-1:123:db:test",
                }
            ]
        }

        resource = _make_resource(
            "main-db",
            "DBInstance",
            {
                "forProvider": {
                    "engine": "postgres",
                    "dbInstanceClass": "db.t3.micro",
                    "publiclyAccessible": False,
                }
            },
        )
        findings = check_rds(session, [resource])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].desired == "False"
        assert findings[0].observed == "True"


class TestIamChecker:
    def test_iam_role_missing(self):
        from xptest.drift.aws_checker import check_iam

        session = MagicMock()
        iam = session.client.return_value
        iam.exceptions.NoSuchEntityException = type("NoSuchEntityException", (Exception,), {})
        iam.get_role.side_effect = iam.exceptions.NoSuchEntityException("not found")

        resource = _make_resource("app-role", "Role", {"forProvider": {"roleName": "app-role"}})
        findings = check_iam(session, [resource])
        assert len(findings) == 1
        assert findings[0].rule == "drift/resource-missing"

    def test_iam_trust_drift(self):
        from xptest.drift.aws_checker import check_iam

        session = MagicMock()
        iam = session.client.return_value
        iam.exceptions.NoSuchEntityException = type("NoSuchEntityException", (Exception,), {})
        iam.get_role.return_value = {
            "Role": {
                "Arn": "arn:aws:iam::123:role/app-role",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                        }
                    ],
                },
            }
        }

        resource = _make_resource(
            "app-role",
            "Role",
            {
                "forProvider": {
                    "roleName": "app-role",
                    "assumeRolePolicyDocument": (
                        '{"Version":"2012-10-17","Statement":'
                        '[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"}}]}'
                    ),
                }
            },
        )
        findings = check_iam(session, [resource])
        assert len(findings) == 1
        assert findings[0].rule == "drift/iam-trust-policy"
        assert findings[0].severity == Severity.CRITICAL


class TestS3Checker:
    def test_s3_encryption_drift(self):
        from xptest.drift.aws_checker import check_s3

        session = MagicMock()
        s3 = session.client.return_value
        error_cls = type("ClientError", (Exception,), {})
        s3.exceptions.ClientError = error_cls
        s3.get_bucket_encryption.side_effect = error_cls(
            "ServerSideEncryptionConfigurationNotFoundError"
        )
        s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}

        resource = _make_resource(
            "data-bucket",
            "Bucket",
            {
                "forProvider": {
                    "bucketName": "test-bucket",
                    "serverSideEncryptionConfiguration": {"rules": []},
                }
            },
        )
        findings = check_s3(session, [resource])
        enc_findings = [f for f in findings if f.rule == "drift/s3-encryption"]
        assert len(enc_findings) == 1
        assert enc_findings[0].severity == Severity.CRITICAL


# ────────────────────────────────────────────────────────
# Integration: drift.run() with mocked session
# ────────────────────────────────────────────────────────


class TestDriftRun:
    @patch("xptest.drift._import_boto3")
    def test_no_credentials_raises(self, mock_boto3):
        from xptest.drift import run as drift_run

        mock_session_cls = MagicMock()
        mock_session = mock_session_cls.return_value
        mock_session.client.return_value.get_caller_identity.side_effect = Exception("no creds")
        mock_boto3.return_value.Session = mock_session_cls

        obj = _make_obj(_make_resource("vpc", "VPC", {"forProvider": {"cidrBlock": "10.0.0.0/16"}}))
        with pytest.raises(DriftError, match="Cannot establish AWS session"):
            drift_run(obj, _config())

    @patch("xptest.drift._import_boto3")
    def test_drift_resource_filter(self, mock_boto3):
        from xptest.drift import run as drift_run

        mock_boto3.return_value = MagicMock()
        session = MagicMock()

        ec2 = MagicMock()
        ec2.describe_vpcs.return_value = {"Vpcs": [{"CidrBlock": "10.0.0.0/16", "VpcId": "vpc-1"}]}
        session.client.return_value = ec2

        obj = _make_obj(
            _make_resource("vpc", "VPC", {"forProvider": {"cidrBlock": "10.0.0.0/16"}}),
            _make_resource("db", "DBInstance", {"forProvider": {"engine": "postgres"}}),
        )
        # Filter to VPC only — RDS should not be checked
        cfg = _config(drift_resource_filter=["VPC"])
        drift_run(obj, cfg, session=session)  # result unused; we assert on mock calls
        # Only VPC checker should run, not RDS
        session.client.assert_called_with("ec2")
