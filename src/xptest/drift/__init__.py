"""Drift detection module — Stage 3 pull-based comparison.

Queries AWS APIs and compares observed state to desired composition spec.
Requires boto3 (optional dependency: pip install xptest[drift]).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
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
from xptest.models import CompositionObject

# Resource kinds handled by each checker
_VPC_KINDS = {"VPC", "Subnet", "SecurityGroup", "RouteTable"}
_S3_KINDS = {"Bucket"}
_RDS_KINDS = {"DBInstance", "DBSubnetGroup", "DBParameterGroup"}
_IAM_KINDS = {"Role", "Policy"}


@dataclass
class DriftReport:
    """Drift detection results with timing metrics (§3.3.4).

    discovery_latency_s: time from start to first finding (seconds).
    remedy_latency_s: time from first finding to last finding (seconds).
    total_duration_s: total drift detection wall-clock time.
    """

    findings: list[DriftFinding] = field(default_factory=list)
    total_duration_s: float = 0.0
    discovery_latency_s: float | None = None
    remedy_latency_s: float | None = None
    resources_checked: int = 0


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
    report = run_with_timing(obj, config, session)
    return report.findings


def run_with_timing(
    obj: CompositionObject,
    config: Config,
    session: Any | None = None,
) -> DriftReport:
    """Run drift detection with discovery/remedy latency timing (§3.3.4).

    Returns a DriftReport containing findings and timing metrics.
    """
    t_start = time.monotonic()

    if session is None:
        boto3 = _import_boto3()
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
    first_finding_time: float | None = None
    last_finding_time: float | None = None

    for checker, checker_resources in [
        (check_vpcs, vpc_resources),
        (check_s3, s3_resources),
        (check_rds, rds_resources),
        (check_iam, iam_resources),
    ]:
        if checker_resources:
            batch = checker(session, checker_resources)
            if batch:
                now = time.monotonic()
                if first_finding_time is None:
                    first_finding_time = now
                last_finding_time = now
            findings.extend(batch)

    t_end = time.monotonic()
    total_duration = t_end - t_start
    discovery_latency = (
        (first_finding_time - t_start) if first_finding_time is not None else None
    )
    remedy_latency = (
        (last_finding_time - first_finding_time)
        if first_finding_time is not None and last_finding_time is not None
        else None
    )

    return DriftReport(
        findings=findings,
        total_duration_s=round(total_duration, 4),
        discovery_latency_s=(
            round(discovery_latency, 4) if discovery_latency is not None else None
        ),
        remedy_latency_s=(
            round(remedy_latency, 4) if remedy_latency is not None else None
        ),
        resources_checked=len(resources),
    )
