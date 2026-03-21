"""Parse Crossplane Composition and XRD YAML into a CompositionObject.

Supports both execution modes:
  - Resources mode: spec.mode == "Resources" (or absent, which defaults to Resources)
  - Pipeline mode:  spec.mode == "Pipeline"

Dependency-edge-relevant patch types (confirmed):
  - FromCompositeFieldPath  (when source reads from status.atProvider.*)
  - CombineFromComposite    (when any source reads from status.atProvider.*)
  - matchLabels selector references
NOT treated as edges:
  - ToCompositeFieldPath
  - FromEnvironmentFieldPath
  - TransformFromComposite
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from xptest.models import ComposedResource, CompositionMode, CompositionObject


class LoadError(ValueError):
    pass


def load(
    composition_path: str,
    xrd_path: str,
    crd_bundle_path: str = "",
) -> CompositionObject:
    """Parse a Composition + XRD YAML pair into a CompositionObject."""
    comp_doc = _read_yaml(composition_path)
    xrd_doc = _read_yaml(xrd_path)

    _assert_kind(comp_doc, "Composition", composition_path)
    _assert_kind(xrd_doc, "CompositeResourceDefinition", xrd_path)

    spec: dict[str, Any] = comp_doc.get("spec", {})
    raw_mode: str = spec.get("mode", "Resources")
    if raw_mode not in ("Resources", "Pipeline"):
        raise LoadError(
            f"{composition_path}: unknown spec.mode '{raw_mode}'; "
            "expected 'Resources' or 'Pipeline'"
        )
    mode = CompositionMode(raw_mode)

    resources = (
        _parse_resources_mode(spec, composition_path)
        if mode == CompositionMode.RESOURCES
        else _parse_pipeline_mode(spec, composition_path)
    )

    return CompositionObject(
        composition_name=_meta_name(comp_doc),
        composition_path=composition_path,
        xrd_name=_meta_name(xrd_doc),
        xrd_path=xrd_path,
        mode=mode,
        resources=resources,
        xrd_spec=xrd_doc.get("spec", {}),
        crd_bundle_path=crd_bundle_path,
    )


# ---------------------------------------------------------------------------
# Mode-specific parsers
# ---------------------------------------------------------------------------


def _parse_resources_mode(spec: dict[str, Any], path: str) -> list[ComposedResource]:
    """Parse spec.resources[] from a Resources-mode Composition."""
    raw_resources: list[dict[str, Any]] = spec.get("resources", [])
    if not raw_resources:
        raise LoadError(f"{path}: spec.resources is empty or missing (mode=Resources)")
    return [_parse_resource_entry(entry, path) for entry in raw_resources]


def _parse_pipeline_mode(spec: dict[str, Any], path: str) -> list[ComposedResource]:
    """Parse composed resources from a Pipeline-mode Composition.

    In Pipeline mode, composed resources live inside function steps that use
    the 'function-patch-and-transform' function. The resources are found at:
      spec.pipeline[].input.resources[]
    Each entry has the same structure as a Resources-mode entry.
    """
    pipeline: list[dict[str, Any]] = spec.get("pipeline", [])
    if not pipeline:
        raise LoadError(f"{path}: spec.pipeline is empty or missing (mode=Pipeline)")

    resources: list[ComposedResource] = []
    for step in pipeline:
        step_input: dict[str, Any] = step.get("input", {})
        step_resources: list[dict[str, Any]] = step_input.get("resources", [])
        for entry in step_resources:
            resources.append(_parse_resource_entry(entry, path))

    if not resources:
        raise LoadError(f"{path}: no composed resources found in any pipeline step (mode=Pipeline)")
    return resources


def _parse_resource_entry(entry: dict[str, Any], path: str) -> ComposedResource:
    """Parse a single resource entry (shared structure across both modes)."""
    name: str = entry.get("name", "")
    if not name:
        raise LoadError(f"{path}: a composed resource entry is missing 'name'")

    base: dict[str, Any] = entry.get("base", {})
    api_version: str = base.get("apiVersion", "")
    kind: str = base.get("kind", "")
    spec: dict[str, Any] = base.get("spec", {})

    patches: list[dict[str, Any]] = entry.get("patches", [])
    readiness_checks: list[dict[str, Any]] = entry.get("readinessChecks", [])

    # Selector: lives under base.spec.forProvider.<resourceRef> or as a top-level
    # matchLabels/matchControllerRef under base.spec. We store the entire
    # forProvider block so Layer 2 can inspect selector fields directly.
    selector: dict[str, Any] | None = _extract_selector(base)

    return ComposedResource(
        name=name,
        api_version=api_version,
        kind=kind,
        spec=spec,
        patches=patches,
        readiness_checks=readiness_checks,
        selector=selector,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_selector(base: dict[str, Any]) -> dict[str, Any] | None:
    """Return the first selector block found in base.spec.forProvider, or None."""
    for_provider: dict[str, Any] = base.get("spec", {}).get("forProvider", {})
    for _key, val in for_provider.items():
        if isinstance(val, dict) and ("matchLabels" in val or "matchControllerRef" in val):
            return val
    return None


def _read_yaml(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise LoadError(f"File not found: {path}")
    with p.open() as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict):
        raise LoadError(f"{path}: expected a YAML mapping, got {type(doc).__name__}")
    return doc


def _assert_kind(doc: dict[str, Any], expected_kind: str, path: str) -> None:
    actual = doc.get("kind", "")
    if actual != expected_kind:
        raise LoadError(f"{path}: expected kind={expected_kind}, got kind={actual}")


def _meta_name(doc: dict[str, Any]) -> str:
    return doc.get("metadata", {}).get("name", "")
