"""Fault injection protocol via observed-state mutation (§7.6, §4.4.5).

Systematic sweep across resources in dependency graph (topological order, leaves first):
  1. Construct fault observed state (Ready=False, atProvider={})
  2. Execute crossplane render with fault state
  3. Check invariants
  4. Emit findings for violations
"""

from __future__ import annotations

import tempfile
from graphlib import TopologicalSorter
from pathlib import Path
from typing import Any

import yaml

from xptest.loader import LoadError
from xptest.logic.models import RenderedGraphSnapshot
from xptest.logic.snapshot import build_snapshot
from xptest.models import ComposedResource, CompositionObject, Finding, Severity


def build_fault_sweep_order(obj: CompositionObject) -> list[str]:
    """Return resource names in reverse topological order (leaves first).

    Uses the Layer 2 dependency graph edges.
    """
    graph: dict[str, set[str]] = {r.name: set() for r in obj.resources}
    resource_names = {r.name for r in obj.resources}

    for r in obj.resources:
        for patch in r.patches:
            patch_type = patch.get("type", "FromCompositeFieldPath")
            if patch_type in ("FromCompositeFieldPath", "CombineFromComposite"):
                from_path = patch.get("fromFieldPath", "")
                parts = from_path.split(".")
                if len(parts) >= 4 and parts[0] == "status" and parts[1] == "atProvider":
                    producer = parts[2]
                    if producer in resource_names and producer != r.name:
                        graph.setdefault(r.name, set()).add(producer)

    try:
        sorter = TopologicalSorter(graph)
        order = list(reversed(list(sorter.static_order())))
    except Exception:
        order = list(graph.keys())

    return order


def generate_fault_observed_resources(
    obj: CompositionObject,
    fault_target: str,
    healthy_status: dict[str, dict[str, Any]] | None = None,
) -> str:
    """Generate observed-resources YAML with fault state for target resource.

    Returns path to temporary YAML file.
    """
    docs: list[dict[str, Any]] = []

    for r in obj.resources:
        if r.name == fault_target:
            doc = _build_fault_resource(r)
        else:
            doc = _build_healthy_resource(r, healthy_status)
        docs.append(doc)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, prefix="xptest-fault-"
    ) as fh:
        yaml.safe_dump_all(docs, fh, sort_keys=False)
        return fh.name


def _build_fault_resource(r: ComposedResource) -> dict[str, Any]:
    """Construct fault observed state: Ready=False, atProvider={}."""
    return {
        "apiVersion": r.api_version,
        "kind": r.kind,
        "metadata": {
            "name": r.name,
            "annotations": {
                "crossplane.io/composition-resource-name": r.name,
            },
        },
        "status": {
            "conditions": [
                {
                    "type": "Ready",
                    "status": "False",
                    "reason": "ReconcileError",
                    "message": "xptest fault injection",
                }
            ],
            "atProvider": {},
        },
    }


def _build_healthy_resource(
    r: ComposedResource,
    healthy_status: dict[str, dict[str, Any]] | None,
) -> dict[str, Any]:
    """Construct healthy observed state for non-target resources."""
    status = {"conditions": [{"type": "Ready", "status": "True"}]}
    if healthy_status and r.name in healthy_status:
        status["atProvider"] = healthy_status[r.name]

    return {
        "apiVersion": r.api_version,
        "kind": r.kind,
        "metadata": {
            "name": r.name,
            "annotations": {
                "crossplane.io/composition-resource-name": r.name,
            },
        },
        "status": status,
    }


def run_fault_injection(
    obj: CompositionObject,
    composition_path: str,
    xr_path: str,
    functions_path: str,
    environment_config_paths: list[str] | None = None,
    healthy_status: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[Finding], list[RenderedGraphSnapshot]]:
    """Execute fault injection sweep and return findings + fault snapshots."""
    from xptest.loader import load as loader_load

    sweep_order = build_fault_sweep_order(obj)
    findings: list[Finding] = []
    fault_snapshots: list[RenderedGraphSnapshot] = []

    for target_name in sweep_order:
        fault_path = generate_fault_observed_resources(
            obj, target_name, healthy_status
        )

        try:
            fault_obj = loader_load(
                composition_path=composition_path,
                xrd_path=obj.xrd_path,
                crd_bundle_path=obj.crd_bundle_path,
                xr_path=xr_path,
                functions_path=functions_path,
                observed_resources_path=fault_path,
                environment_config_paths=environment_config_paths or [],
            )

            case_id = f"fault|{target_name}"
            snapshot = build_snapshot(
                fault_obj,
                case_id=case_id,
                input_flat={"fault_target": target_name},
            )
            fault_snapshots.append(snapshot)

            # Check if target resource disappeared from output
            rendered_names = {r.name for r in fault_obj.resources}
            if target_name not in rendered_names:
                findings.append(Finding(
                    layer=7,
                    rule="fi/resource-disappeared-under-fault",
                    resource=target_name,
                    path="",
                    severity=Severity.WARNING,
                    message=(
                        f"Resource '{target_name}' disappeared from render output "
                        f"when injected with ReconcileError fault."
                    ),
                    remediation=(
                        "Ensure template conditions handle NotReady state "
                        "without dropping resources."
                    ),
                    finding_id="fi/resource-disappeared-under-fault",
                    category="fault-injection",
                    case_id=case_id,
                ))

        except LoadError as exc:
            findings.append(Finding(
                layer=7,
                rule="fi/render-failed-under-fault",
                resource=target_name,
                path="",
                severity=Severity.CRITICAL,
                message=(
                    f"Render failed when '{target_name}' was faulted: {exc}"
                ),
                remediation=(
                    "Template cannot handle resource failure state. "
                    "Add error handling in composition logic."
                ),
                finding_id="fi/render-failed-under-fault",
                category="fault-injection",
                case_id=f"fault|{target_name}",
            ))
        finally:
            Path(fault_path).unlink(missing_ok=True)

    return findings, fault_snapshots
