"""Automatic offline perturbation generation and destructive-change analysis."""

from __future__ import annotations

from copy import deepcopy

from xptest.chaos.criticality import classify_criticality
from xptest.chaos.models import DestructiveChangeFinding, PerturbationScenario
from xptest.logic.models import RenderedGraphSnapshot
from xptest.models import Severity


def generate_perturbations(snapshot: RenderedGraphSnapshot) -> list[PerturbationScenario]:
    scenarios: list[PerturbationScenario] = []
    if snapshot.resources:
        scenarios.append(
            PerturbationScenario(
                perturbation_id="P1-remove-first-resource",
                kind="remove_resource",
                params={"resource_id": snapshot.resources[0].resource_id},
            )
        )
    if snapshot.edges:
        scenarios.append(
            PerturbationScenario(
                perturbation_id="P2-remove-first-edge",
                kind="remove_edge",
                params={"edge": list(snapshot.edges[0])},
            )
        )
    if len(snapshot.resources) >= 1:
        scenarios.append(
            PerturbationScenario(
                perturbation_id="P3-rename-first-identity",
                kind="rename_identity",
                params={"resource_id": snapshot.resources[0].resource_id, "suffix": "-renamed"},
            )
        )
    if len(snapshot.resources) >= 2:
        scenarios.append(
            PerturbationScenario(
                perturbation_id="P4-partial-output-truncation",
                kind="partial_truncation",
                params={"keep": 1},
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

    return mutated


def analyze_destructive_change(
    baseline: RenderedGraphSnapshot,
    mutated: RenderedGraphSnapshot,
    perturbation_id: str,
) -> list[DestructiveChangeFinding]:
    findings: list[DestructiveChangeFinding] = []
    criticality = classify_criticality(baseline)

    base_ids = {r.resource_id for r in baseline.resources}
    mut_ids = {r.resource_id for r in mutated.resources}

    removed = sorted(base_ids - mut_ids)
    added = sorted(mut_ids - base_ids)

    for rid in removed:
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

    if added and removed:
        findings.append(
            DestructiveChangeFinding(
                finding_id="C2-replacement-risk",
                category="destructive-change",
                severity=Severity.CRITICAL,
                case_id=mutated.case_id,
                baseline_case_id=baseline.case_id,
                perturbation_id=perturbation_id,
                resource_id=",".join(removed),
                evidence={"removed": removed, "added": added},
                remediation=(
                    "Check conditions and naming to avoid unintended "
                    "replacement transitions."
                ),
            )
        )

    if len(removed) >= 2:
        findings.append(
            DestructiveChangeFinding(
                finding_id="C3-cascade-risk",
                category="destructive-change",
                severity=Severity.CRITICAL,
                case_id=mutated.case_id,
                baseline_case_id=baseline.case_id,
                perturbation_id=perturbation_id,
                resource_id="",
                evidence={"removed_count": len(removed), "removed": removed},
                remediation=(
                    "Review dependency boundaries; protect unrelated resources "
                    "from cascade."
                ),
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
        findings.append(
            DestructiveChangeFinding(
                finding_id="C5-partial-output-risk",
                category="destructive-change",
                severity=Severity.CRITICAL,
                case_id=mutated.case_id,
                baseline_case_id=baseline.case_id,
                perturbation_id=perturbation_id,
                resource_id="",
                evidence={
                    "baseline_count": len(baseline.resources),
                    "mutated_count": len(mutated.resources),
                },
                remediation="Guard against partial render outputs before applying changes.",
            )
        )

    return findings


def _escalate(base: Severity, criticality_level: str) -> Severity:
    if criticality_level == "critical":
        return Severity.CRITICAL
    if criticality_level == "high" and base == Severity.INFO:
        return Severity.WARNING
    return base
