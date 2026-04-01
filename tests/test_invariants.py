"""Tests for resource preservation invariants (Phase 5D)."""

from __future__ import annotations

from xptest.exploration.invariants import (
    check_deletion_policy_escalation,
    check_minimum_resource_count,
    check_type_coverage,
    collect_baseline_deletion_policies,
    collect_declared_gvks,
    compute_baseline_min_count,
)
from xptest.logic.models import RenderedGraphSnapshot, RenderedResourceNode
from xptest.models import Severity


def _node(
    name: str,
    kind: str = "Bucket",
    api_version: str = "s3.aws/v1",
    spec: dict | None = None,
) -> RenderedResourceNode:
    return RenderedResourceNode(
        resource_id=f"{api_version}|{kind}|{name}",
        role=name,
        api_version=api_version,
        kind=kind,
        name=name,
        spec=spec or {},
        identity_source="composition-resource-name",
    )


def _snapshot(
    case_id: str,
    nodes: list[RenderedResourceNode],
) -> RenderedGraphSnapshot:
    return RenderedGraphSnapshot(
        case_id=case_id,
        input_flat={},
        resources=nodes,
        edges=[],
        graph_hash="",
    )


def test_type_coverage_all_present():
    s = _snapshot("c1", [_node("a"), _node("b", kind="Role", api_version="iam/v1")])
    declared = collect_declared_gvks([s])
    findings = check_type_coverage(declared, [s])
    assert findings == []


def test_type_coverage_missing_gvk():
    full = _snapshot("c1", [_node("a"), _node("b", kind="Role", api_version="iam/v1")])
    partial = _snapshot("c2", [_node("a")])
    declared = collect_declared_gvks([full])
    findings = check_type_coverage(declared, [partial])
    assert len(findings) == 1
    assert findings[0].rule == "inv/type-coverage"
    assert findings[0].severity == Severity.CRITICAL


def test_deletion_policy_escalation_detected():
    baseline_policies = {"bucket": "Orphan"}
    node = _node("bucket", spec={"deletionPolicy": "Delete"})
    findings = check_deletion_policy_escalation(baseline_policies, [_snapshot("c1", [node])])
    assert len(findings) == 1
    assert findings[0].rule == "inv/deletion-policy-escalation"


def test_deletion_policy_no_escalation():
    baseline_policies = {"bucket": "Delete"}
    node = _node("bucket", spec={"deletionPolicy": "Delete"})
    findings = check_deletion_policy_escalation(baseline_policies, [_snapshot("c1", [node])])
    assert findings == []


def test_minimum_resource_count_below_baseline():
    s = _snapshot("c1", [_node("a")])
    findings = check_minimum_resource_count(baseline_min_count=3, snapshots=[s])
    assert len(findings) == 1
    assert findings[0].rule == "inv/minimum-resource-count"
    assert findings[0].severity == Severity.WARNING


def test_minimum_resource_count_ok():
    s = _snapshot("c1", [_node("a"), _node("b"), _node("c")])
    findings = check_minimum_resource_count(baseline_min_count=3, snapshots=[s])
    assert findings == []


def test_fault_cases_excluded_from_min_count():
    fault_s = _snapshot("fault|vpc", [_node("a")])
    findings = check_minimum_resource_count(
        baseline_min_count=3, snapshots=[fault_s], exclude_fault_cases=True
    )
    assert findings == []


def test_compute_baseline_min_count():
    s1 = _snapshot("c1", [_node("a"), _node("b")])
    s2 = _snapshot("c2", [_node("a"), _node("b"), _node("c")])
    assert compute_baseline_min_count([s1, s2]) == 2


def test_collect_declared_gvks():
    s = _snapshot("c1", [_node("a"), _node("b", kind="Role", api_version="iam/v1")])
    gvks = collect_declared_gvks([s])
    assert ("s3.aws/v1", "Bucket") in gvks
    assert ("iam/v1", "Role") in gvks


def test_collect_baseline_deletion_policies():
    s = _snapshot(
        "c1",
        [
            _node("a", spec={"deletionPolicy": "Orphan"}),
            _node("b", spec={"deletionPolicy": "Delete"}),
        ],
    )
    policies = collect_baseline_deletion_policies([s])
    assert policies["a"] == "Orphan"
    assert policies["b"] == "Delete"
