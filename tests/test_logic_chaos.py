from __future__ import annotations

from xptest.chaos.engine import (
    analyze_destructive_change,
    apply_perturbation,
    generate_perturbations,
)
from xptest.cli import _run_logic_phase
from xptest.logic.coverage import compute_coverage, nearby_pairs
from xptest.logic.heuristics import find_nearby_diff_heuristics, find_snapshot_heuristics
from xptest.logic.snapshot import build_snapshot
from xptest.models import ComposedResource, CompositionMode, CompositionObject, Severity


def _obj(case_name: str, resources: list[ComposedResource]) -> CompositionObject:
    return CompositionObject(
        composition_name=f"comp-{case_name}",
        composition_path=f"/{case_name}/composition.yaml",
        xrd_name="xexample",
        xrd_path=f"/{case_name}/xrd.yaml",
        mode=CompositionMode.PIPELINE,
        resources=resources,
        xrd_spec={},
        crd_bundle_path="",
    )


def _resource(name: str, kind: str = "Bucket") -> ComposedResource:
    return ComposedResource(
        name=name,
        api_version="s3.aws.upbound.io/v1beta1",
        kind=kind,
        spec={"forProvider": {"region": "us-east-1"}},
    )


def test_snapshot_duplicate_role_detected() -> None:
    obj = _obj("dup", [_resource("shared"), _resource("shared")])
    snapshot = build_snapshot(obj, case_id="case-0", input_flat={"spec.env": "dev"})

    findings = find_snapshot_heuristics(snapshot)

    assert any(f.finding_id == "L5-H01/duplicate-semantic-role" for f in findings)
    assert any(f.finding_id == "L5-H02/duplicate-resource-identity" for f in findings)


def test_nearby_diff_large_shift_small_input() -> None:
    baseline_obj = _obj(
        "a",
        [_resource("r1"), _resource("r2", kind="Subnet"), _resource("r3"), _resource("r4")],
    )
    changed_obj = _obj("b", [_resource("r1")])

    snap_a = build_snapshot(baseline_obj, case_id="a", input_flat={"spec.env": "dev"})
    snap_b = build_snapshot(changed_obj, case_id="b", input_flat={"spec.env": "prod"})

    pairs = nearby_pairs([snap_a, snap_b], max_distance=1)
    findings = find_nearby_diff_heuristics({"a": snap_a, "b": snap_b}, pairs)

    assert any(f.finding_id == "L5-D03/large-shift-small-input" for f in findings)


def test_perturbation_removal_escalates_critical_kind() -> None:
    baseline_obj = _obj("p", [_resource("db-main", kind="DBInstance"), _resource("bucket")])
    baseline = build_snapshot(baseline_obj, case_id="baseline", input_flat={"spec.size": 1})

    scenarios = generate_perturbations(baseline, profile="synthetic")
    remove = next(s for s in scenarios if s.kind == "remove_resource")
    mutated = apply_perturbation(baseline, remove)
    findings = analyze_destructive_change(
        baseline,
        mutated,
        perturbation_id=remove.perturbation_id,
        scenario=remove,
    )

    c1 = [f for f in findings if f.finding_id == "C1-disappearance-risk"]
    assert c1
    assert any(f.severity == Severity.CRITICAL for f in c1)


def test_coverage_counts_unique_graphs() -> None:
    obj_a = _obj("c1", [_resource("a")])
    obj_b = _obj("c2", [_resource("b")])

    snap_a = build_snapshot(obj_a, case_id="c1", input_flat={"spec.team": "alpha"})
    snap_b = build_snapshot(obj_b, case_id="c2", input_flat={"spec.team": "beta"})

    records, summary = compute_coverage([snap_a, snap_b])

    assert len(records) == 2
    assert summary.total_cases == 2
    assert summary.unique_graphs == 2


def test_runtime_outage_expected_removals_do_not_trigger_c3_c5() -> None:
    baseline_obj = _obj(
        "runtime",
        [
            _resource("aws-sm-master-user-credentials", kind="XSecretKeeper"),
            _resource("db-subnet-group", kind="DBSubnetGroup"),
        ],
    )
    baseline = build_snapshot(baseline_obj, case_id="baseline", input_flat={})

    scenario = next(
        s
        for s in generate_perturbations(baseline, profile="runtime")
        if s.perturbation_id == "R1-external-secret-outage"
    )
    # Force this scenario to remove both resources as expected.
    scenario.params["targets"] = [r.resource_id for r in baseline.resources]
    scenario.params["expected_removed"] = [r.resource_id for r in baseline.resources]

    mutated = apply_perturbation(baseline, scenario)
    findings = analyze_destructive_change(
        baseline,
        mutated,
        perturbation_id=scenario.perturbation_id,
        scenario=scenario,
    )

    rules = {f.finding_id for f in findings}
    assert "C3-cascade-risk" not in rules
    assert "C5-partial-output-risk" not in rules


def test_chaos_dedup_uses_structure_not_graph_hash() -> None:
    obj_a = _obj(
        "a",
        [
            ComposedResource(
                name="aws-sm-master-user-credentials",
                api_version="crossplane.swisscom.com/v1alpha1",
                kind="XSecretKeeper",
                spec={"forProvider": {"region": "eu-central-1"}},
            ),
            ComposedResource(
                name="db-subnet-group",
                api_version="database.aws.crossplane.io/v1beta1",
                kind="DBSubnetGroup",
                spec={"forProvider": {"name": "a"}},
            ),
        ],
    )
    obj_b = _obj(
        "b",
        [
            ComposedResource(
                name="aws-sm-master-user-credentials",
                api_version="crossplane.swisscom.com/v1alpha1",
                kind="XSecretKeeper",
                spec={"forProvider": {"region": "us-east-1"}},
            ),
            ComposedResource(
                name="db-subnet-group",
                api_version="database.aws.crossplane.io/v1beta1",
                kind="DBSubnetGroup",
                spec={"forProvider": {"name": "b"}},
            ),
        ],
    )

    findings, sections = _run_logic_phase(
        runs=[
            ("case-a", obj_a, {"spec.a": 1}),
            ("case-b", obj_b, {"spec.a": 2}),
        ],
        nearby_distance=0,
        auto_perturb=True,
        chaos_profile="runtime",
        persist=False,
        artifact_root="xptest-artifacts",
    )

    assert sections["logic"]["coverage"]["total_cases"] == 2
    assert sections["perturbation"]["unique_baselines"] == 1
    assert sections["perturbation"]["dedup_skipped"] == 1
    assert isinstance(findings, list)
