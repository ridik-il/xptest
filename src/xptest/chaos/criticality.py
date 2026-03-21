"""Automatic criticality scoring for rendered resources."""

from __future__ import annotations

from collections import Counter

from xptest.chaos.models import CriticalityClassification
from xptest.logic.models import RenderedGraphSnapshot

_CRITICAL_KINDS = {
    "DBInstance",
    "RDSInstance",
    "Bucket",
    "Role",
    "Subnet",
    "VPC",
    "SecurityGroup",
}


def classify_criticality(snapshot: RenderedGraphSnapshot) -> dict[str, CriticalityClassification]:
    fan_out = Counter(src for src, _dst in snapshot.edges)
    result: dict[str, CriticalityClassification] = {}
    for node in snapshot.resources:
        reasons: list[str] = []
        level = "normal"
        if node.kind in _CRITICAL_KINDS:
            level = "critical"
            reasons.append("critical_kind")
        if fan_out.get(node.resource_id, 0) >= 2:
            if level != "critical":
                level = "high"
            reasons.append("dependency_fanout")
        if "db" in node.role.lower() or "state" in node.role.lower():
            if level == "normal":
                level = "high"
            reasons.append("persistent_role_hint")

        result[node.resource_id] = CriticalityClassification(
            resource_id=node.resource_id,
            level=level,
            reasons=reasons,
        )
    return result
