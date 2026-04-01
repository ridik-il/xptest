"""Resource preservation invariants (§7.7, §4.4.6).

Three invariants enforced across all render outputs:
  1. Type coverage — every declared GVK appears in at least one render
  2. Deletion policy escalation — Orphan→Delete is flagged
  3. Minimum resource count — non-fault renders must not contract below baseline minimum
"""

from __future__ import annotations

from xptest.logic.models import RenderedGraphSnapshot
from xptest.models import Finding, Severity


def check_type_coverage(
    declared_gvks: set[tuple[str, str]],
    snapshots: list[RenderedGraphSnapshot],
) -> list[Finding]:
    """Invariant 1: every declared (apiVersion, kind) must appear in ≥1 render."""
    rendered_gvks: set[tuple[str, str]] = set()
    for s in snapshots:
        for node in s.resources:
            rendered_gvks.add((node.api_version, node.kind))

    findings: list[Finding] = []
    for api_version, kind in sorted(declared_gvks - rendered_gvks):
        findings.append(
            Finding(
                layer=7,
                rule="inv/type-coverage",
                resource=f"{api_version}/{kind}",
                path="",
                severity=Severity.CRITICAL,
                message=(
                    f"Resource type {api_version}/{kind} declared in composition "
                    f"but absent from all {len(snapshots)} render outputs."
                ),
                remediation=(
                    "Verify template conditions; ensure every declared resource type "
                    "is reachable by at least one parameter combination."
                ),
                finding_id="inv/type-coverage",
                category="invariant",
            )
        )
    return findings


def check_deletion_policy_escalation(
    baseline_policies: dict[str, str],
    snapshots: list[RenderedGraphSnapshot],
) -> list[Finding]:
    """Invariant 2: Orphan→Delete escalation across renders."""
    findings: list[Finding] = []
    for s in snapshots:
        for node in s.resources:
            baseline_dp = baseline_policies.get(node.name, "")
            current_dp = node.spec.get("deletionPolicy", "Delete")
            if baseline_dp == "Orphan" and current_dp == "Delete":
                findings.append(
                    Finding(
                        layer=7,
                        rule="inv/deletion-policy-escalation",
                        resource=node.name,
                        path="spec.deletionPolicy",
                        severity=Severity.CRITICAL,
                        message=(
                            f"Resource '{node.name}' deletionPolicy changed from "
                            f"Orphan to Delete in case '{s.case_id}'."
                        ),
                        remediation=(
                            "Confirm deletion policy change is safe. "
                            "Update baseline if intentional."
                        ),
                        finding_id="inv/deletion-policy-escalation",
                        category="invariant",
                        case_id=s.case_id,
                    )
                )
    return findings


def check_minimum_resource_count(
    baseline_min_count: int,
    snapshots: list[RenderedGraphSnapshot],
    exclude_fault_cases: bool = True,
) -> list[Finding]:
    """Invariant 3: non-fault renders must not produce fewer resources than baseline min."""
    findings: list[Finding] = []
    for s in snapshots:
        # Skip fault-injected cases (identified by "|" in case_id from perturbation)
        if exclude_fault_cases and "|" in s.case_id:
            continue

        count = len(s.resources)
        if count < baseline_min_count:
            findings.append(
                Finding(
                    layer=7,
                    rule="inv/minimum-resource-count",
                    resource="",
                    path="",
                    severity=Severity.WARNING,
                    message=(
                        f"Case '{s.case_id}' rendered {count} resources, "
                        f"below baseline minimum of {baseline_min_count}."
                    ),
                    remediation=(
                        "Review parameter combination; this input causes resource-set "
                        "contraction that may indicate a template bug."
                    ),
                    finding_id="inv/minimum-resource-count",
                    category="invariant",
                    case_id=s.case_id,
                )
            )
    return findings


def collect_declared_gvks(
    snapshots: list[RenderedGraphSnapshot],
) -> set[tuple[str, str]]:
    """Collect all unique (apiVersion, kind) pairs across all renders."""
    gvks: set[tuple[str, str]] = set()
    for s in snapshots:
        for node in s.resources:
            gvks.add((node.api_version, node.kind))
    return gvks


def collect_baseline_deletion_policies(
    snapshots: list[RenderedGraphSnapshot],
) -> dict[str, str]:
    """Build map of resource name → first-seen deletionPolicy."""
    policies: dict[str, str] = {}
    for s in snapshots:
        for node in s.resources:
            if node.name not in policies:
                policies[node.name] = node.spec.get("deletionPolicy", "Delete")
    return policies


def compute_baseline_min_count(
    snapshots: list[RenderedGraphSnapshot],
) -> int:
    """Compute minimum resource count across non-fault snapshots."""
    counts = [len(s.resources) for s in snapshots if "|" not in s.case_id and s.resources]
    return min(counts) if counts else 0
