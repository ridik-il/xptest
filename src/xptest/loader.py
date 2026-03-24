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

import re
import subprocess
import tempfile
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
    xr_path: str | None = None,
    functions_path: str | None = None,
    observed_resources_path: str | None = None,
    environment_config_paths: list[str] | None = None,
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

    if xr_path and functions_path:
        xrd_spec = xrd_doc.get("spec", {})
        xrd_group = xrd_spec.get("group", "")
        xrd_kind = xrd_spec.get("names", {}).get("kind", "")
        xrd_versions = xrd_spec.get("versions", [])
        xrd_version = xrd_versions[0].get("name", "") if xrd_versions else ""
        xrd_api_version = f"{xrd_group}/{xrd_version}" if xrd_group and xrd_version else ""

        resources = _parse_from_render(
            composition_path=composition_path,
            xr_path=xr_path,
            functions_path=functions_path,
            observed_resources_path=observed_resources_path,
            environment_config_paths=environment_config_paths or [],
            xrd_api_version=xrd_api_version,
            xrd_kind=xrd_kind,
        )
    else:
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
        environment_config_paths=environment_config_paths or [],
    )


def _parse_from_render(
    composition_path: str,
    xr_path: str,
    functions_path: str,
    observed_resources_path: str | None,
    environment_config_paths: list[str],
    xrd_api_version: str,
    xrd_kind: str,
) -> list[ComposedResource]:
    """Render Composition via Crossplane CLI and parse resulting managed resources."""
    rendered = _run_crossplane_render(
        composition_path=composition_path,
        xr_path=xr_path,
        functions_path=functions_path,
        observed_resources_path=observed_resources_path,
        environment_config_paths=environment_config_paths,
    )

    docs = list(yaml.safe_load_all(rendered))
    resources: list[ComposedResource] = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue

        api_version = str(doc.get("apiVersion", ""))
        kind = str(doc.get("kind", ""))
        if not api_version or not kind:
            continue

        # Exclude top-level control-plane resources from analysis payload.
        if kind in {"Composition", "CompositeResourceDefinition"}:
            continue
        # Exclude the rendered XR itself; we only validate composed/managed resources.
        if xrd_api_version and xrd_kind and api_version == xrd_api_version and kind == xrd_kind:
            continue

        metadata = doc.get("metadata", {})
        name = _rendered_resource_name(metadata)
        resources.append(
            ComposedResource(
                name=name,
                api_version=api_version,
                kind=kind,
                spec=doc.get("spec", {}),
                patches=[],
                readiness_checks=[],
                selector=_extract_selector({"spec": doc.get("spec", {})}),
            )
        )

    if not resources:
        raise LoadError(
            "crossplane render produced no composed resources. "
            "Verify --xr, --functions, and optional --observed-resources inputs."
        )

    return resources


def _run_crossplane_render(
    composition_path: str,
    xr_path: str,
    functions_path: str,
    observed_resources_path: str | None,
    environment_config_paths: list[str],
) -> str:
    timeout_seconds = 300
    temp_functions_path: str | None = None
    candidate_function_paths = [functions_path]
    rewritten = _rewrite_functions_for_docker_runtime(functions_path)
    if rewritten is not None:
        temp_functions_path = rewritten
        candidate_function_paths.append(rewritten)

    try:
        last_error = ""
        for candidate_functions_path in candidate_function_paths:
            base_args = [xr_path, composition_path, candidate_functions_path]
            for env_path in environment_config_paths:
                base_args.extend(["-e", env_path])
            if observed_resources_path:
                base_args.append(f"--observed-resources={observed_resources_path}")

            commands = [
                ["crossplane", "beta", "render", *base_args],
                ["crossplane", "render", *base_args],
            ]

            for cmd in commands:
                try:
                    result = subprocess.run(
                        cmd,
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=timeout_seconds,
                    )
                except FileNotFoundError:
                    raise LoadError(
                        "crossplane CLI not found. Install Crossplane CLI to use render mode."
                    ) from None
                except subprocess.TimeoutExpired:
                    raise LoadError(
                        f"crossplane render timed out after {timeout_seconds} seconds"
                    ) from None

                if result.returncode == 0:
                    return result.stdout

                stderr = (result.stderr or "").lower()
                if "unexpected argument render" in stderr or "unknown command \"beta\"" in stderr:
                    last_error = result.stderr.strip() or result.stdout.strip()
                    continue
                if "unknown command \"render\"" in stderr:
                    last_error = result.stderr.strip() or result.stdout.strip()
                    continue

                last_error = result.stderr.strip() or result.stdout.strip() or "unknown error"

        raise LoadError(
            "crossplane render failed: "
            f"{last_error or 'render command is unavailable in this Crossplane CLI version'}"
        )
    finally:
        if temp_functions_path:
            Path(temp_functions_path).unlink(missing_ok=True)


def _rewrite_functions_for_docker_runtime(functions_path: str) -> str | None:
    """Strip development-runtime annotations so render can run in Docker mode.

    Returns a temp file path when rewrites are needed, otherwise None.
    """
    p = Path(functions_path)
    if not p.exists():
        return None

    with p.open() as fh:
        docs = list(yaml.safe_load_all(fh))

    changed = False
    rewritten_docs: list[Any] = []
    for doc in docs:
        if not isinstance(doc, dict):
            rewritten_docs.append(doc)
            continue

        metadata = doc.get("metadata", {})
        annotations = metadata.get("annotations", {})
        if not isinstance(annotations, dict):
            rewritten_docs.append(doc)
            continue

        keys_to_remove = [
            k for k in annotations.keys() if k.startswith("render.crossplane.io/runtime")
        ]
        if keys_to_remove:
            changed = True
            for k in keys_to_remove:
                annotations.pop(k, None)

        rewritten_docs.append(doc)

    if not changed:
        return None

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as temp:
        yaml.safe_dump_all(rewritten_docs, temp, sort_keys=False)
        return temp.name


def _rendered_resource_name(metadata: dict[str, Any]) -> str:
    annotations = metadata.get("annotations", {})

    render_name = annotations.get("crossplane.io/composition-resource-name")
    if isinstance(render_name, str) and render_name:
        return render_name

    gt_name = annotations.get("gotemplating.fn.crossplane.io/composition-resource-name")
    if isinstance(gt_name, str) and gt_name:
        return gt_name

    meta_name = metadata.get("name", "")
    if isinstance(meta_name, str) and meta_name:
        return meta_name

    return "rendered-resource"


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
    for step_index, step in enumerate(pipeline):
        step_input: dict[str, Any] = step.get("input", {})
        step_resources: list[dict[str, Any]] = step_input.get("resources", [])
        for entry in step_resources:
            resources.append(_parse_resource_entry(entry, path))

        # Constrained support for function-go-templating inline templates.
        # We strip template control lines and replace inline template expressions
        # so YAML documents can be parsed into composed resources.
        resources.extend(_parse_go_templating_inline(step, path, step_index))

    if not resources:
        raise LoadError(f"{path}: no composed resources found in any pipeline step (mode=Pipeline)")
    return resources


def _parse_go_templating_inline(
    step: dict[str, Any],
    path: str,
    step_index: int,
) -> list[ComposedResource]:
    step_input: dict[str, Any] = step.get("input", {})
    if step_input.get("kind") != "GoTemplate":
        return []

    inline_block: dict[str, Any] = step_input.get("inline", {})
    template: str = inline_block.get("template", "")
    if not isinstance(template, str) or not template.strip():
        return []

    docs = _parse_go_template_to_docs(template)
    resources: list[ComposedResource] = []

    for doc_index, doc in enumerate(docs):
        api_version = str(doc.get("apiVersion", ""))
        kind = str(doc.get("kind", ""))
        if not api_version or not kind:
            continue

        metadata = doc.get("metadata", {})
        name = _go_template_resource_name(metadata, step_index, doc_index)

        resources.append(
            ComposedResource(
                name=name,
                api_version=api_version,
                kind=kind,
                spec=doc.get("spec", {}),
                patches=[],
                readiness_checks=[],
                selector=_extract_selector({"spec": doc.get("spec", {})}),
            )
        )

    return resources


def _parse_go_template_to_docs(template: str) -> list[dict[str, Any]]:
    sanitized_lines: list[str] = []
    for line in template.splitlines():
        stripped = line.strip()
        if _is_go_template_control_line(stripped):
            continue
        sanitized_lines.append(_replace_template_expressions(line))

    sanitized = "\n".join(sanitized_lines)
    docs: list[dict[str, Any]] = []
    for doc in yaml.safe_load_all(sanitized):
        if isinstance(doc, dict):
            docs.append(doc)
    return docs


def _is_go_template_control_line(stripped: str) -> bool:
    if not stripped.startswith("{{"):
        return False
    if not stripped.endswith("}}"):
        return False

    body = stripped[2:-2].strip()
    if not body:
        return True
    if body.startswith("/*"):
        return True

    control_prefixes = (
        "if ",
        "end",
        "with ",
        "range ",
        "else",
        "$",
    )
    return body.startswith(control_prefixes)


def _replace_template_expressions(line: str) -> str:
    return re.sub(r"{{[^{}]*}}", "xptest-templated", line)


def _go_template_resource_name(
    metadata: dict[str, Any],
    step_index: int,
    doc_index: int,
) -> str:
    annotations = metadata.get("annotations", {})
    ann_name = annotations.get("gotemplating.fn.crossplane.io/composition-resource-name")
    if isinstance(ann_name, str) and ann_name and "xptest-templated" not in ann_name:
        return ann_name

    meta_name = metadata.get("name", "")
    if isinstance(meta_name, str) and meta_name and "xptest-templated" not in meta_name:
        return meta_name

    return f"go-template-step-{step_index}-doc-{doc_index}"


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
