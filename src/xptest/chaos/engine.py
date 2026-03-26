"""Automatic offline perturbation generation and destructive-change analysis."""

from __future__ import annotations

from copy import deepcopy
from typing import Iterable

from xptest.chaos.criticality import classify_criticality
from xptest.chaos.models import DestructiveChangeFinding, PerturbationScenario
from xptest.logic.models import RenderedGraphSnapshot
from xptest.models import Severity


def generate_perturbations(
    snapshot: RenderedGraphSnapshot,
    profile: str = "runtime",
) -> list[PerturbationScenario]:
    scenarios: list[PerturbationScenario] = []

    if profile in {"synthetic", "both"} and snapshot.resources:
        scenarios.append(
            PerturbationScenario(
                perturbation_id="P1-remove-first-resource",
                kind="remove_resource",
                params={"resource_id": snapshot.resources[0].resource_id},
            )
        )
    if profile in {"synthetic", "both"} and snapshot.edges:
        scenarios.append(
            PerturbationScenario(
                perturbation_id="P2-remove-first-edge",
                kind="remove_edge",
                params={"edge": list(snapshot.edges[0])},
            )
        )
    if profile in {"synthetic", "both"} and len(snapshot.resources) >= 1:
        scenarios.append(
            PerturbationScenario(
                perturbation_id="P3-rename-first-identity",
                kind="rename_identity",
                params={"resource_id": snapshot.resources[0].resource_id, "suffix": "-renamed"},
            )
        )
    if profile in {"synthetic", "both"} and len(snapshot.resources) >= 2:
        scenarios.append(
            PerturbationScenario(
                perturbation_id="P4-partial-output-truncation",
                kind="partial_truncation",
                params={"keep": 1},
            )
        )

    if profile in {"runtime", "both"}:
        secret_ids = [
            r.resource_id
            for r in snapshot.resources
            if _looks_secret_related((r.resource_id, r.kind, r.role, r.name))
        ]
        if secret_ids:
            scenarios.append(
                PerturbationScenario(
                    perturbation_id="R1-external-secret-outage",
                    kind="runtime_outage_remove_set",
                    params={
                        "targets": secret_ids,
                        "expected_removed": secret_ids,
                        "reason": "external-secret-controller-unavailable",
                    },
                )
            )

        provider_ids = [
            r.resource_id
            for r in snapshot.resources
            if _looks_provider_related((r.resource_id, r.kind, r.role, r.name))
        ]
        if provider_ids:
            scenarios.append(
                PerturbationScenario(
                    perturbation_id="R2-provider-connectivity-outage",
                    kind="runtime_outage_remove_set",
                    params={
                        "targets": provider_ids,
                        "expected_removed": provider_ids,
                        "reason": "provider-connectivity-issues",
                    },
                )
            )

        # R3: Network / subnet dependency absence
        network_ids = [
            r.resource_id
            for r in snapshot.resources
            if _looks_network_related((r.resource_id, r.kind, r.role, r.name))
        ]
        if network_ids:
            scenarios.append(
                PerturbationScenario(
                    perturbation_id="R3-network-dependency-absence",
                    kind="runtime_outage_remove_set",
                    params={
                        "targets": network_ids,
                        "expected_removed": network_ids,
                        "reason": "subnet-or-security-group-not-ready",
                    },
                )
            )

        # R4: IAM / policy attachment gap
        iam_ids = [
            r.resource_id
            for r in snapshot.resources
            if _looks_iam_related((r.resource_id, r.kind, r.role, r.name))
        ]
        if iam_ids:
            scenarios.append(
                PerturbationScenario(
                    perturbation_id="R4-iam-policy-gap",
                    kind="runtime_outage_remove_set",
                    params={
                        "targets": iam_ids,
                        "expected_removed": iam_ids,
                        "reason": "iam-role-or-policy-attachment-missing",
                    },
                )
            )

        # R5: Database/stateful resource unavailability (dependency-not-ready)
        # Simulates the most critical resource in the graph being not-ready,
        # which blocks downstream resources.
        db_ids = [
            r.resource_id
            for r in snapshot.resources
            if _looks_database_related((r.resource_id, r.kind, r.role, r.name))
        ]
        if db_ids:
            scenarios.append(
                PerturbationScenario(
                    perturbation_id="R5-database-not-ready",
                    kind="runtime_outage_remove_set",
                    params={
                        "targets": db_ids[:1],  # just the first DB resource
                        "expected_removed": db_ids[:1],
                        "reason": "db-cluster-not-ready-blocks-downstream",
                    },
                )
            )

        # R6: High-fanout dependency removal — remove the resource with
        # the highest dependency fanout (most dependents) to test cascade impact.
        if snapshot.edges:
            from collections import Counter

            fanout = Counter(src for src, _dst in snapshot.edges)
            if fanout:
                hub_id = fanout.most_common(1)[0][0]
                scenarios.append(
                    PerturbationScenario(
                        perturbation_id="R6-hub-dependency-removal",
                        kind="runtime_outage_remove_set",
                        params={
                            "targets": [hub_id],
                            "expected_removed": [hub_id],
                            "reason": "highest-fanout-dependency-removed",
                        },
                    )
                )

    return scenarios


def apply_perturbation(
    snapshot: RenderedGraphSnapshot,
    scenario: PerturbationScenario,
) -> RenderedGraphSnapshot:
    mutated = deepcopy(snapshot)
    mutated.case_id = f"{snapshot.case_id}|{scenario.perturbation_id}"

    if scenario.kind == "remove_resource":
        rid = scenario.params.get("resource_id", "")
        mutated.resources = [r for r in mutated.resources if r.resource_id != rid]
        mutated.edges = [e for e in mutated.edges if rid not in e]
    elif scenario.kind == "remove_edge":
        edge = tuple(scenario.params.get("edge", []))
        mutated.edges = [e for e in mutated.edges if tuple(e) != edge]
    elif scenario.kind == "rename_identity":
        rid = scenario.params.get("resource_id", "")
        suffix = scenario.params.get("suffix", "-renamed")
        for r in mutated.resources:
            if r.resource_id == rid:
                r.resource_id = f"{r.resource_id}{suffix}"
    elif scenario.kind == "partial_truncation":
        keep = max(0, int(scenario.params.get("keep", 1)))
        kept = mutated.resources[:keep]
        kept_ids = {r.resource_id for r in kept}
        mutated.resources = kept
        mutated.edges = [e for e in mutated.edges if e[0] in kept_ids and e[1] in kept_ids]
    elif scenario.kind == "runtime_outage_remove_set":
        target_ids = set(str(v) for v in scenario.params.get("targets", []))
        related = _expand_related_ids(mutated.edges, target_ids, max_hops=2)
        remove_ids = target_ids | related
        mutated.resources = [r for r in mutated.resources if r.resource_id not in remove_ids]
        mutated.edges = [
            e
            for e in mutated.edges
            if e[0] not in remove_ids and e[1] not in remove_ids
        ]

    return mutated


def analyze_destructive_change(
    baseline: RenderedGraphSnapshot,
    mutated: RenderedGraphSnapshot,
    perturbation_id: str,
    scenario: PerturbationScenario | None = None,
) -> list[DestructiveChangeFinding]:
    findings: list[DestructiveChangeFinding] = []
    criticality = classify_criticality(baseline)

    base_ids = {r.resource_id for r in baseline.resources}
    mut_ids = {r.resource_id for r in mutated.resources}

    removed = sorted(base_ids - mut_ids)
    added = sorted(mut_ids - base_ids)

    expected_removed: set[str] = set()
    if scenario and scenario.kind == "runtime_outage_remove_set":
        expected_removed = set(str(v) for v in scenario.params.get("expected_removed", []))

    removed_for_c1 = removed
    if expected_removed:
        removed_for_c1 = [rid for rid in removed if rid not in expected_removed]

    for rid in removed_for_c1:
        level = criticality.get(rid).level if rid in criticality else "normal"
        severity = _escalate(Severity.WARNING, level)
        findings.append(
            DestructiveChangeFinding(
                finding_id="C1-disappearance-risk",
                category="destructive-change",
                severity=severity,
                case_id=mutated.case_id,
                baseline_case_id=baseline.case_id,
                perturbation_id=perturbation_id,
                resource_id=rid,
                evidence={"removed": rid, "criticality": level},
                remediation="Stabilize resource identity and prevent unintended drops.",
            )
        )

    if expected_removed:
        collateral_removed = [rid for rid in removed if rid not in expected_removed]
        if collateral_removed:
            collateral_has_data = any(_looks_data_plane_related(rid) for rid in collateral_removed)
            findings.append(
                DestructiveChangeFinding(
                    finding_id="C6-runtime-outage-cascade",
                    category="destructive-change",
                    severity=Severity.CRITICAL if collateral_has_data else Severity.WARNING,
                    case_id=mutated.case_id,
                    baseline_case_id=baseline.case_id,
                    perturbation_id=perturbation_id,
                    resource_id="",
                    evidence={
                        "expected_removed": sorted(expected_removed),
                        "collateral_removed": collateral_removed,
                    },
                    remediation=(
                        "A runtime outage should not prune unrelated resources from desired state. "
                        "Review go-template conditions and dependency guards for outage paths."
                    ),
                )
            )

    if added and removed:
        replacement_severity = Severity.CRITICAL
        replacement_remediation = (
            "Check conditions and naming to avoid unintended "
            "replacement transitions."
        )
        if perturbation_id == "P3-rename-first-identity":
            # In rename perturbation scenarios, replacement is expected and
            # should be informational unless other destructive signals appear.
            replacement_severity = Severity.INFO
            replacement_remediation = (
                "Rename perturbation intentionally changes identity. "
                "Treat this as expected unless combined with cascade or partial-output risks."
            )

        findings.append(
            DestructiveChangeFinding(
                finding_id="C2-replacement-risk",
                category="destructive-change",
                severity=replacement_severity,
                case_id=mutated.case_id,
                baseline_case_id=baseline.case_id,
                perturbation_id=perturbation_id,
                resource_id=",".join(removed),
                evidence={"removed": removed, "added": added},
                remediation=replacement_remediation,
            )
        )

    # C3: cascade risk — only counts *unexpected* removals (collateral damage).
    # When a runtime_outage scenario intentionally removes N resources, those
    # are expected, not a cascade.
    unexpected_removed = [rid for rid in removed if rid not in expected_removed]
    if len(unexpected_removed) >= 2:
        cascade_severity = Severity.CRITICAL
        cascade_remediation = (
            "Review dependency boundaries; protect unrelated resources "
            "from cascade."
        )
        if perturbation_id == "P4-partial-output-truncation":
            cascade_severity = Severity.INFO
            cascade_remediation = (
                "Synthetic truncation intentionally removes multiple resources. "
                "Use this as resilience signal, not a production-critical alert by itself."
            )

        findings.append(
            DestructiveChangeFinding(
                finding_id="C3-cascade-risk",
                category="destructive-change",
                severity=cascade_severity,
                case_id=mutated.case_id,
                baseline_case_id=baseline.case_id,
                perturbation_id=perturbation_id,
                resource_id="",
                evidence={
                    "removed_count": len(unexpected_removed),
                    "removed": unexpected_removed,
                },
                remediation=cascade_remediation,
            )
        )

    if set(baseline.edges) != set(mutated.edges):
        findings.append(
            DestructiveChangeFinding(
                finding_id="C4-unsafe-dependency-drift",
                category="destructive-change",
                severity=Severity.WARNING,
                case_id=mutated.case_id,
                baseline_case_id=baseline.case_id,
                perturbation_id=perturbation_id,
                resource_id="",
                evidence={"baseline_edges": baseline.edges, "mutated_edges": mutated.edges},
                remediation="Inspect dependency producers/consumers and preserve critical edges.",
            )
        )

    if len(mutated.resources) < len(baseline.resources) and len(mutated.resources) <= 1:
        partial_severity = Severity.CRITICAL
        partial_remediation = "Guard against partial render outputs before applying changes."
        if perturbation_id == "P4-partial-output-truncation":
            partial_severity = Severity.INFO
            partial_remediation = (
                "Synthetic truncation intentionally collapsed the output. "
                "Treat this as expected for this perturbation. "
                "Use it only to assess blast radius."
            )

        findings.append(
            DestructiveChangeFinding(
                finding_id="C5-partial-output-risk",
                category="destructive-change",
                severity=partial_severity,
                case_id=mutated.case_id,
                baseline_case_id=baseline.case_id,
                perturbation_id=perturbation_id,
                resource_id="",
                evidence={
                    "baseline_count": len(baseline.resources),
                    "mutated_count": len(mutated.resources),
                },
                remediation=partial_remediation,
            )
        )

    return findings


def _escalate(base: Severity, criticality_level: str) -> Severity:
    if criticality_level == "critical":
        return Severity.CRITICAL
    if criticality_level == "high" and base == Severity.INFO:
        return Severity.WARNING
    return base


def _expand_related_ids(
    edges: Iterable[tuple[str, str]],
    seeds: set[str],
    max_hops: int,
) -> set[str]:
    if not seeds or max_hops <= 0:
        return set()

    adjacency: dict[str, set[str]] = {}
    for a, b in edges:
        adjacency.setdefault(a, set()).add(b)
        adjacency.setdefault(b, set()).add(a)

    visited = set(seeds)
    frontier = set(seeds)
    related: set[str] = set()

    for _ in range(max_hops):
        next_frontier: set[str] = set()
        for node in frontier:
            for neigh in adjacency.get(node, set()):
                if neigh not in visited:
                    visited.add(neigh)
                    next_frontier.add(neigh)
                    related.add(neigh)
        if not next_frontier:
            break
        frontier = next_frontier

    return related


def _looks_secret_related(fields: tuple[str, str, str, str]) -> bool:
    text = "|".join(fields).lower()
    hints = ("secret", "xsecretkeeper", "externalsecret", "credentials")
    return any(h in text for h in hints)


def _looks_provider_related(fields: tuple[str, str, str, str]) -> bool:
    text = "|".join(fields).lower()
    hints = ("providerconfig", "provider", "awsprovider", "provider-aws")
    return any(h in text for h in hints)


def _looks_data_plane_related(resource_id: str) -> bool:
    text = resource_id.lower()
    hints = ("db", "database", "rds", "aurora", "cluster", "instance")
    return any(h in text for h in hints)


def _looks_network_related(fields: tuple[str, str, str, str]) -> bool:
    text = "|".join(fields).lower()
    hints = (
        "subnet", "securitygroup", "xsecuritygroup", "dbsubnetgroup",
        "vpc", "routetable", "networkacl", "sg-",
    )
    return any(h in text for h in hints)


def _looks_iam_related(fields: tuple[str, str, str, str]) -> bool:
    text = "|".join(fields).lower()
    hints = ("role", "policy", "iam", "serviceaccount")
    return any(h in text for h in hints)


def _looks_database_related(fields: tuple[str, str, str, str]) -> bool:
    text = "|".join(fields).lower()
    hints = ("dbcluster", "dbinstance", "aurora", "rds", "database")
    return any(h in text for h in hints)
