"""Drift detection module — Stage 3 pull-based comparison.

Queries AWS APIs and compares observed state to desired composition spec.
Requires boto3 (optional dependency: pip install xptest[drift]).
"""

from __future__ import annotations

from typing import Any

from xptest.config import Config
from xptest.drift.aws_checker import (
    _import_boto3,
    check_iam,
    check_rds,
    check_s3,
    check_vpcs,
)
from xptest.drift.models import DriftError, DriftFinding
from xptest.models import ComposedResource, CompositionObject

# Resource kinds handled by each checker
_VPC_KINDS = {"VPC", "Subnet", "SecurityGroup", "RouteTable"}
_S3_KINDS = {"Bucket"}
_RDS_KINDS = {"DBInstance", "DBSubnetGroup", "DBParameterGroup"}
_IAM_KINDS = {"Role", "Policy"}


def run(
    obj: CompositionObject,
    config: Config,
    session: Any | None = None,
) -> list[DriftFinding]:
    """Run drift detection against AWS for all composed resources.

    Args:
        obj: Parsed composition object with desired resource specs.
        config: xptest configuration (aws_region used if session is None).
        session: Optional pre-configured boto3.Session. If None, one is
                 created using the default credential chain.

    Returns:
        List of DriftFinding objects for detected mismatches.

    Raises:
        DriftError: If AWS credentials are missing or API calls fail.
    """
    boto3 = _import_boto3()

    if session is None:
        try:
            kwargs = {}
            if config.aws_region:
                kwargs["region_name"] = config.aws_region
            session = boto3.Session(**kwargs)
            # Verify credentials are available
            session.client("sts").get_caller_identity()
        except Exception as exc:
            raise DriftError(
                f"Cannot establish AWS session: {exc}. "
                "Ensure AWS credentials are configured (OIDC in CI, or local profile)."
            ) from exc

    # Partition resources by family
    resources = obj.resources
    if config.drift_resource_filter:
        allowed = set(config.drift_resource_filter)
        resources = [r for r in resources if r.kind in allowed]

    vpc_resources = [r for r in resources if r.kind in _VPC_KINDS]
    s3_resources = [r for r in resources if r.kind in _S3_KINDS]
    rds_resources = [r for r in resources if r.kind in _RDS_KINDS]
    iam_resources = [r for r in resources if r.kind in _IAM_KINDS]

    findings: list[DriftFinding] = []

    if vpc_resources:
        findings.extend(check_vpcs(session, vpc_resources))
    if s3_resources:
        findings.extend(check_s3(session, s3_resources))
    if rds_resources:
        findings.extend(check_rds(session, rds_resources))
    if iam_resources:
        findings.extend(check_iam(session, iam_resources))

    return findings
