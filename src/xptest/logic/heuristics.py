"""Heuristic finding generation for logic-test snapshots and nearby diffs."""

from __future__ import annotations

from collections import Counter
from typing import Any

from xptest.logic.models import DiffFinding, NearbyPair, RenderedGraphSnapshot
from xptest.models import Severity


def find_snapshot_heuristics(snapshot: RenderedGraphSnapshot) -> list[DiffFinding]:
    findings: list[DiffFinding] = []

    role_counts = Counter(n.role for n in snapshot.resources)
    for role, count in role_counts.items():
        if count > 1:
            findings.append(
                DiffFinding(
                    finding_id="L5-H01/duplicate-semantic-role",
                    category="logic-heuristic",
                    severity=Severity.CRITICAL,
                    case_id=snapshot.case_id,
                    baseline_case_id="",
                    resource_id=role,
                    evidence={
                        "message": (
                            f"Duplicate semantic role '{role}' detected ({count} resources)."
                        ),
                        "count": count,
                    },
                    remediation=(
                        "Ensure composition-resource-name annotations remain unique per role."
                    ),
                )
            )

    identity_counts = Counter(n.resource_id for n in snapshot.resources)
    for rid, count in identity_counts.items():
        if count > 1:
            findings.append(
                DiffFinding(
                    finding_id="L5-H02/duplicate-resource-identity",
                    category="logic-heuristic",
                    severity=Severity.CRITICAL,
                    case_id=snapshot.case_id,
                    baseline_case_id="",
                    resource_id=rid,
                    evidence={
                        "message": f"Duplicate resource identity '{rid}' detected ({count}).",
                        "count": count,
                    },
                    remediation=(
                        "Stabilize naming and annotation identity for rendered resources."
                    ),
                )
            )

    return findings


def find_nearby_diff_heuristics(
    snapshots: dict[str, RenderedGraphSnapshot],
    pairs: list[NearbyPair],
) -> list[DiffFinding]:
    findings: list[DiffFinding] = []
    for pair in pairs:
        a = snapshots[pair.case_a]
        b = snapshots[pair.case_b]

        a_ids = {n.resource_id for n in a.resources}
        b_ids = {n.resource_id for n in b.resources}

        removed = sorted(a_ids - b_ids)
        added = sorted(b_ids - a_ids)

        if removed:
            findings.append(
                DiffFinding(
                    finding_id="L5-D01/unexpected-resource-removal",
                    category="nearby-diff",
                    severity=Severity.WARNING,
                    case_id=b.case_id,
                    baseline_case_id=a.case_id,
                    resource_id=",".join(removed),
                    evidence={
                        "message": "Nearby input change removed rendered resources.",
                        "removed": removed,
                        "distance": pair.distance,
                    },
                    remediation="Review branch guards to ensure required resources are stable.",
                )
            )

        if added:
            findings.append(
                DiffFinding(
                    finding_id="L5-D02/unexpected-resource-addition",
                    category="nearby-diff",
                    severity=Severity.WARNING,
                    case_id=b.case_id,
                    baseline_case_id=a.case_id,
                    resource_id=",".join(added),
                    evidence={
                        "message": "Nearby input change added new rendered resources.",
                        "added": added,
                        "distance": pair.distance,
                    },
                    remediation="Review conditional rendering logic for overly sensitive branches.",
                )
            )

        if pair.distance <= 1 and (len(removed) + len(added)) >= 3:
            changed_field = (
                _find_changed_field(a.input_flat, b.input_flat) if pair.distance == 1 else None
            )
            high_impact = changed_field is not None and _is_high_impact_field(changed_field)
            severity = Severity.WARNING if high_impact else Severity.CRITICAL
            evidence: dict[str, Any] = {
                "message": "Small input delta caused large rendered graph shift.",
                "distance": pair.distance,
                "added_count": len(added),
                "removed_count": len(removed),
            }
            if changed_field is not None:
                evidence["changed_field"] = changed_field
            if high_impact:
                evidence["high_impact_field"] = changed_field
            findings.append(
                DiffFinding(
                    finding_id="L5-D03/large-shift-small-input",
                    category="nearby-diff",
                    severity=severity,
                    case_id=b.case_id,
                    baseline_case_id=a.case_id,
                    resource_id="",
                    evidence=evidence,
                    remediation=(
                        "Harden branch conditions or split high-impact logic into "
                        "explicit feature flags."
                    ),
                )
            )

        if _edges_changed(a, b):
            findings.append(
                DiffFinding(
                    finding_id="L5-D04/dependency-edge-shift",
                    category="nearby-diff",
                    severity=Severity.WARNING,
                    case_id=b.case_id,
                    baseline_case_id=a.case_id,
                    resource_id="",
                    evidence={
                        "message": "Dependency edges changed across nearby input cases.",
                        "distance": pair.distance,
                    },
                    remediation="Review dependency-bearing fields and generated references.",
                )
            )

    return findings


_HIGH_IMPACT_EXACT = frozenset(
    {
        "engine",
        "provider",
        "platform",
        "runtime",
        "architecture",
    }
)

_HIGH_IMPACT_SUFFIXES = frozenset(
    {
        "engine",
        "type",
        "kind",
        "mode",
        "tier",
        "family",
        "version",
        "provider",
        "platform",
        "class",
    }
)


def _is_high_impact_field(field_name: str) -> bool:
    """Check if the last segment of a dotted field path indicates a high-impact variant change."""
    last = field_name.rsplit(".", maxsplit=1)[-1]
    lower = last.lower()
    # Exact match on the full last segment (handles single-word fields)
    if lower in _HIGH_IMPACT_EXACT:
        return True
    # Suffix match for compound camelCase names (e.g. storageType, instanceType,
    # engineVersion, dbInstanceClass) — only when the segment has a prefix before
    # the suffix (avoids matching bare "type" or "mode" as high-impact).
    if len(lower) > max(len(s) for s in _HIGH_IMPACT_SUFFIXES):
        return any(lower.endswith(s) for s in _HIGH_IMPACT_SUFFIXES)
    return False


def _find_changed_field(
    a_flat: dict[str, Any],
    b_flat: dict[str, Any],
) -> str | None:
    """Return the single key that differs between two input_flat dicts, or None."""
    all_keys = a_flat.keys() | b_flat.keys()
    changed = [k for k in all_keys if a_flat.get(k) != b_flat.get(k)]
    return changed[0] if len(changed) == 1 else None


def _edges_changed(a: RenderedGraphSnapshot, b: RenderedGraphSnapshot) -> bool:
    return set(a.edges) != set(b.edges)
