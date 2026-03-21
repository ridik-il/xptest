"""Dataclasses for offline logic testing sessions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from xptest.models import Finding, Severity


@dataclass
class RenderedResourceNode:
    resource_id: str
    role: str
    api_version: str
    kind: str
    name: str
    spec: dict[str, Any]
    identity_source: str


@dataclass
class RenderedGraphSnapshot:
    case_id: str
    input_flat: dict[str, Any]
    resources: list[RenderedResourceNode] = field(default_factory=list)
    edges: list[tuple[str, str]] = field(default_factory=list)
    graph_hash: str = ""


@dataclass
class CoverageRecord:
    case_id: str
    resource_presence_signature: str
    field_signature: str


@dataclass
class LogicCoverageSummary:
    total_cases: int
    unique_graphs: int
    unique_presence_signatures: int
    unique_field_signatures: int


@dataclass
class NearbyPair:
    case_a: str
    case_b: str
    distance: int


@dataclass
class DiffFinding:
    finding_id: str
    category: str
    severity: Severity
    case_id: str
    baseline_case_id: str
    resource_id: str
    evidence: dict[str, Any]
    remediation: str

    def to_finding(self) -> Finding:
        return Finding(
            layer=5,
            rule=self.finding_id,
            resource=self.resource_id,
            path="",
            severity=self.severity,
            message=self.evidence.get("message", self.finding_id),
            remediation=self.remediation,
            finding_id=self.finding_id,
            category=self.category,
            case_id=self.case_id,
            baseline_case_id=self.baseline_case_id,
            evidence=self.evidence,
        )
