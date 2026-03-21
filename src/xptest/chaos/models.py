"""Dataclasses for automatic offline perturbation analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from xptest.models import Severity


@dataclass
class PerturbationScenario:
    perturbation_id: str
    kind: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class CriticalityClassification:
    resource_id: str
    level: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class DestructiveChangeFinding:
    finding_id: str
    category: str
    severity: Severity
    case_id: str
    baseline_case_id: str
    perturbation_id: str
    resource_id: str
    evidence: dict[str, Any]
    remediation: str
