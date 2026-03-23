"""Tests for breaking change detection (Phase 5B)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from xptest.exploration.breaking_change import (
    detect_breaking_changes,
    load_baseline,
    save_baseline,
)
from xptest.logic.models import RenderedGraphSnapshot, RenderedResourceNode
from xptest.models import Severity


def _node(name: str, kind: str = "Bucket", spec: dict | None = None) -> RenderedResourceNode:
    return RenderedResourceNode(
        resource_id=f"s3.aws/v1|{kind}|{name}",
        role=name,
        api_version="s3.aws/v1",
        kind=kind,
        name=name,
        spec=spec or {"forProvider": {"region": "us-east-1"}},
        identity_source="composition-resource-name",
    )


def _snapshot(case_id: str, nodes: list[RenderedResourceNode]) -> RenderedGraphSnapshot:
    return RenderedGraphSnapshot(
        case_id=case_id,
        input_flat={},
        resources=nodes,
        edges=[],
        graph_hash="abc123",
    )


def test_no_breaking_changes_when_matching():
    baseline = {
        "composition": "test",
        "resources": [
            {
                "composition-resource-name": "bucket",
                "external-name": "my-bucket",
                "deletionPolicy": "Delete",
                "managementPolicies": ["*"],
            }
        ],
    }
    snapshots = [_snapshot("c1", [_node("bucket")])]
    findings = detect_breaking_changes(baseline, snapshots)
    assert len(findings) == 0


def test_resource_removed_detected():
    baseline = {
        "composition": "test",
        "resources": [
            {
                "composition-resource-name": "old-bucket",
                "external-name": "",
                "deletionPolicy": "Delete",
                "managementPolicies": ["*"],
            }
        ],
    }
    snapshots = [_snapshot("c1", [_node("new-bucket")])]
    findings = detect_breaking_changes(baseline, snapshots)
    assert any(f.rule == "bc/resource-removed" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_deletion_policy_escalated():
    baseline = {
        "composition": "test",
        "resources": [
            {
                "composition-resource-name": "bucket",
                "external-name": "",
                "deletionPolicy": "Orphan",
                "managementPolicies": ["*"],
            }
        ],
    }
    node = _node("bucket", spec={"deletionPolicy": "Delete", "forProvider": {}})
    snapshots = [_snapshot("c1", [node])]
    findings = detect_breaking_changes(baseline, snapshots)
    assert any(f.rule == "bc/deletion-policy-escalated" for f in findings)


def test_management_delete_added():
    baseline = {
        "composition": "test",
        "resources": [
            {
                "composition-resource-name": "bucket",
                "external-name": "",
                "deletionPolicy": "Delete",
                "managementPolicies": ["Observe", "Create", "Update"],
            }
        ],
    }
    node = _node(
        "bucket",
        spec={
            "managementPolicies": ["Observe", "Create", "Update", "Delete"],
            "forProvider": {},
        },
    )
    snapshots = [_snapshot("c1", [node])]
    findings = detect_breaking_changes(baseline, snapshots)
    assert any(f.rule == "bc/management-delete-added" for f in findings)


def test_empty_baseline_no_findings():
    findings = detect_breaking_changes({}, [_snapshot("c1", [_node("a")])])
    assert findings == []


def test_save_and_load_baseline():
    snapshots = [_snapshot("c1", [_node("bucket"), _node("role", kind="Role")])]
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
        path = fh.name

    try:
        save_baseline(snapshots, "my-comp", path)
        loaded = load_baseline(path)
        assert loaded["composition"] == "my-comp"
        assert len(loaded["resources"]) == 2
        names = {r["composition-resource-name"] for r in loaded["resources"]}
        assert names == {"bucket", "role"}
    finally:
        Path(path).unlink(missing_ok=True)
