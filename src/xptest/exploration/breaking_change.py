"""Breaking change detection against golden baseline (§7.5, §4.4.4).

Maintains a committed baseline storing per-resource identity and lifecycle metadata.
Compares render outputs against baseline to detect destructive changes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from xptest.logic.models import RenderedGraphSnapshot
from xptest.models import Finding, Severity


@dataclass
class BaselineResource:
    composition_resource_name: str
    external_name: str
    deletion_policy: str
    management_policies: list[str]


def save_baseline(
    snapshots: list[RenderedGraphSnapshot],
    composition_name: str,
    output_path: str,
) -> None:
    """Write golden baseline JSON from render results."""
    resources: list[dict[str, Any]] = []
    seen: set[str] = set()

    for snapshot in snapshots:
        for node in snapshot.resources:
            if node.resource_id in seen:
                continue
            seen.add(node.resource_id)
            resources.append({
                "composition-resource-name": node.name,
                "external-name": _extract_external_name(node.spec),
                "deletionPolicy": _extract_deletion_policy(node.spec),
                "managementPolicies": _extract_management_policies(node.spec),
            })

    baseline = {
        "composition": composition_name,
        "resources": resources,
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(baseline, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def load_baseline(path: str) -> dict[str, Any]:
    """Read existing baseline JSON."""
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def detect_breaking_changes(
    baseline: dict[str, Any],
    current_snapshots: list[RenderedGraphSnapshot],
) -> list[Finding]:
    """Compare render outputs against baseline; emit findings for 4 bc rules."""
    if not baseline or "resources" not in baseline:
        return []

    baseline_resources = {
        r["composition-resource-name"]: r
        for r in baseline.get("resources", [])
    }

    # Collect all rendered resource names across all snapshots
    rendered_names: set[str] = set()
    current_by_name: dict[str, dict[str, Any]] = {}
    for snapshot in current_snapshots:
        for node in snapshot.resources:
            rendered_names.add(node.name)
            if node.name not in current_by_name:
                current_by_name[node.name] = {
                    "deletionPolicy": _extract_deletion_policy(node.spec),
                    "managementPolicies": _extract_management_policies(node.spec),
                    "resource_id": node.resource_id,
                }

    findings: list[Finding] = []

    # bc/resource-removed: baseline resource absent from all renders
    for name in baseline_resources:
        if name not in rendered_names:
            findings.append(Finding(
                layer=7,
                rule="bc/resource-removed",
                resource=name,
                path="",
                severity=Severity.CRITICAL,
                message=(
                    f"Resource '{name}' present in baseline but absent from "
                    f"all render outputs."
                ),
                remediation=(
                    "Verify the resource was intentionally removed. "
                    "Update the baseline with an explicit reviewed commit."
                ),
                finding_id="bc/resource-removed",
                category="breaking-change",
            ))

    # Per-resource rules for resources present in both baseline and renders
    for name in rendered_names & set(baseline_resources.keys()):
        base_res = baseline_resources[name]
        curr_res = current_by_name[name]

        # bc/deletion-policy-escalated
        base_dp = base_res.get("deletionPolicy", "")
        curr_dp = curr_res.get("deletionPolicy", "")
        if base_dp == "Orphan" and curr_dp == "Delete":
            findings.append(Finding(
                layer=7,
                rule="bc/deletion-policy-escalated",
                resource=name,
                path="spec.deletionPolicy",
                severity=Severity.CRITICAL,
                message=(
                    f"Resource '{name}' deletionPolicy escalated from "
                    f"Orphan to Delete."
                ),
                remediation=(
                    "Confirm deletion policy change is intentional. "
                    "Update baseline after review."
                ),
                finding_id="bc/deletion-policy-escalated",
                category="breaking-change",
            ))

        # bc/management-delete-added
        base_mp = set(base_res.get("managementPolicies", []))
        curr_mp = set(curr_res.get("managementPolicies", []))
        if "Delete" not in base_mp and "Delete" in curr_mp:
            findings.append(Finding(
                layer=7,
                rule="bc/management-delete-added",
                resource=name,
                path="spec.managementPolicies",
                severity=Severity.CRITICAL,
                message=(
                    f"Resource '{name}' gained Delete verb in "
                    f"managementPolicies (was: {sorted(base_mp)}, "
                    f"now: {sorted(curr_mp)})."
                ),
                remediation=(
                    "Verify Delete verb addition is intentional. "
                    "Update baseline after review."
                ),
                finding_id="bc/management-delete-added",
                category="breaking-change",
            ))

    return findings


def _extract_external_name(spec: dict[str, Any]) -> str:
    """Extract crossplane.io/external-name from metadata annotations or spec."""
    return spec.get("forProvider", {}).get("name", "")


def _extract_deletion_policy(spec: dict[str, Any]) -> str:
    return spec.get("deletionPolicy", "Delete")


def _extract_management_policies(spec: dict[str, Any]) -> list[str]:
    policies = spec.get("managementPolicies", ["*"])
    if isinstance(policies, list):
        return policies
    return ["*"]
