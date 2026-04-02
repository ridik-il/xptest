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

from xptest.models import ComposedResource, CompositionMode, CompositionObject, RenderMode


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
    render_mode: str = "auto",
    *,
    _comp_doc: dict[str, Any] | None = None,
    _xrd_doc: dict[str, Any] | None = None,
) -> CompositionObject:
    """Parse a Composition + XRD YAML pair into a CompositionObject.

    Args:
        render_mode: How to handle pipeline-mode go-templating compositions.
            "auto" — try real render via crossplane CLI, fall back to degraded
            "render" — require real render, fail if unavailable
            "offline" — always use offline parsing (degraded for go-templating)
        _comp_doc: Pre-parsed composition dict (avoids re-reading YAML from disk).
        _xrd_doc: Pre-parsed XRD dict (avoids re-reading YAML from disk).
    """
    comp_doc = _comp_doc if _comp_doc is not None else _read_yaml(composition_path)
    xrd_doc = _xrd_doc if _xrd_doc is not None else _read_yaml(xrd_path)

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

    xrd_spec = xrd_doc.get("spec", {})
    xrd_group = xrd_spec.get("group", "")
    xrd_kind = xrd_spec.get("names", {}).get("kind", "")
    xrd_versions = xrd_spec.get("versions", [])
    xrd_version = xrd_versions[0].get("name", "") if xrd_versions else ""
    xrd_api_version = f"{xrd_group}/{xrd_version}" if xrd_group and xrd_version else ""

    resources: list[ComposedResource] = []
    actual_render_mode = RenderMode.STATIC_PARSE

    if xr_path and functions_path and render_mode != "offline":
        # Explicit render inputs provided — use crossplane render
        resources = _parse_from_render(
            composition_path=composition_path,
            xr_path=xr_path,
            functions_path=functions_path,
            observed_resources_path=observed_resources_path,
            environment_config_paths=environment_config_paths or [],
            xrd_api_version=xrd_api_version,
            xrd_kind=xrd_kind,
        )
        actual_render_mode = RenderMode.RENDER
    elif mode == CompositionMode.RESOURCES:
        resources = _parse_resources_mode(spec, composition_path)
        actual_render_mode = RenderMode.STATIC_PARSE
    elif mode == CompositionMode.PIPELINE:
        resources, actual_render_mode = _load_pipeline_resources(
            composition_path=composition_path,
            xrd_path=xrd_path,
            comp_doc=comp_doc,
            spec=spec,
            functions_path=functions_path,
            environment_config_paths=environment_config_paths or [],
            observed_resources_path=observed_resources_path,
            xrd_api_version=xrd_api_version,
            xrd_kind=xrd_kind,
            render_mode=render_mode,
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
        render_mode=actual_render_mode,
    )


def _load_pipeline_resources(
    composition_path: str,
    xrd_path: str,
    comp_doc: dict[str, Any],
    spec: dict[str, Any],
    functions_path: str | None,
    environment_config_paths: list[str],
    observed_resources_path: str | None,
    xrd_api_version: str,
    xrd_kind: str,
    render_mode: str,
) -> tuple[list[ComposedResource], RenderMode]:
    """Load resources from a pipeline-mode composition.

    For compositions with go-templating steps, tries real rendering
    first (unless render_mode="offline"), then falls back to degraded
    offline parsing.

    Returns (resources, render_mode_used).
    """
    from xptest.render import (
        RenderError,
        RenderUnavailable,
        auto_render_pipeline,
        has_go_templating_steps,
    )

    uses_go_templates = has_go_templating_steps(comp_doc)

    # If no go-templating, static parse works fine for PaT steps
    if not uses_go_templates:
        return _parse_pipeline_mode(spec, composition_path), RenderMode.STATIC_PARSE

    # For go-templating compositions, try real render
    if render_mode != "offline":
        try:
            rendered = auto_render_pipeline(
                composition_path=composition_path,
                xrd_path=xrd_path,
                functions_path=functions_path,
                environment_config_paths=environment_config_paths,
                observed_resources_path=observed_resources_path,
            )
            resources = _parse_rendered_output(rendered, xrd_api_version, xrd_kind)
            if resources:
                return resources, RenderMode.RENDER
        except RenderUnavailable:
            if render_mode == "render":
                raise LoadError(
                    f"{composition_path}: composition uses go-templating but "
                    "crossplane CLI is not available for rendering. "
                    "Install the Crossplane CLI and Docker, or use "
                    "--render-mode=auto to allow degraded offline parsing."
                ) from None
            # Fall through to degraded parse
        except RenderError as exc:
            if render_mode == "render":
                raise LoadError(
                    f"{composition_path}: crossplane render failed: {exc}. stderr: {exc.stderr}"
                ) from None
            # Fall through to degraded parse

    # Degraded offline parse: strip templates and parse what we can.
    # This is the legacy behavior — it works for simple templates but
    # fails on conditionals, ranges, and structural template expressions.
    import sys

    sys.stderr.write(
        f"xptest: WARNING — '{composition_path}' uses go-templating but "
        "rendering is unavailable. Using degraded offline parse; "
        "results may be incomplete or incorrect. "
        "Install crossplane CLI + Docker for accurate analysis.\n"
    )
    try:
        resources = _parse_pipeline_mode(spec, composition_path)
        return resources, RenderMode.DEGRADED_PARSE
    except (LoadError, yaml.YAMLError):
        # Even degraded parse failed — return empty with clear error
        sys.stderr.write(
            f"xptest: WARNING — degraded offline parse also failed for "
            f"'{composition_path}'. Go template expressions produced "
            "invalid YAML. No resources could be extracted.\n"
        )
        return [], RenderMode.DEGRADED_PARSE


def _parse_rendered_output(
    rendered_yaml: str,
    xrd_api_version: str,
    xrd_kind: str,
) -> list[ComposedResource]:
    """Parse crossplane render output into ComposedResource list.

    Filters out the XR itself and control-plane resources, keeping
    only composed/managed resources.
    """
    docs = list(yaml.safe_load_all(rendered_yaml))
    resources: list[ComposedResource] = []

    for doc in docs:
        if not isinstance(doc, dict):
            continue

        api_version = str(doc.get("apiVersion", ""))
        kind = str(doc.get("kind", ""))
        if not api_version or not kind:
            continue

        # Skip control-plane resources
        if kind in {"Composition", "CompositeResourceDefinition", "Function"}:
            continue
        # Skip the rendered XR itself
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

    return resources


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
    try:
        rendered = _run_crossplane_render(
            composition_path=composition_path,
            xr_path=xr_path,
            functions_path=functions_path,
            observed_resources_path=observed_resources_path,
            environment_config_paths=environment_config_paths,
        )
    except LoadError:
        # Fall back to render.py which handles Development-mode functions natively
        from xptest.render import RenderError, RenderUnavailable, render_composition

        xr_yaml = Path(xr_path).read_text()
        functions_yaml = Path(functions_path).read_text()
        try:
            rendered = render_composition(
                composition_path=composition_path,
                xr_yaml=xr_yaml,
                functions_yaml=functions_yaml,
                environment_config_paths=environment_config_paths,
                observed_resources_path=observed_resources_path,
            )
        except (RenderError, RenderUnavailable) as exc:
            raise LoadError(str(exc)) from exc

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
    global _working_render_cmd, _working_functions_variant  # noqa: PLW0603

    timeout_seconds = 300
    temp_files: list[str] = []

    # --- Fast path: reuse proven command + functions variant ---
    if _working_render_cmd is not None and _working_functions_variant is not None:
        fn_path = _resolve_functions_variant(
            functions_path,
            _working_functions_variant,
        )
        base_args = _build_render_args(
            xr_path,
            composition_path,
            fn_path,
            environment_config_paths,
            observed_resources_path,
        )
        cmd = [*_working_render_cmd, *base_args]
        try:
            result = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            if result.returncode == 0:
                return result.stdout
            # If the cached variant fails (e.g. different composition structure),
            # fall through to full discovery.
        except FileNotFoundError:
            raise LoadError(
                "crossplane CLI not found. Install Crossplane CLI to use render mode."
            ) from None
        except subprocess.TimeoutExpired:
            raise LoadError(f"crossplane render timed out after {timeout_seconds}s") from None
        finally:
            temp_files.clear()

    # --- Discovery path: try all combinations, cache the first winner ---

    # Build candidate functions.yaml variants (cached per functions_path).
    candidate_variants = _get_functions_variants(functions_path, temp_files)

    try:
        last_error = ""
        for variant_key, candidate_fn_path in candidate_variants:
            base_args = _build_render_args(
                xr_path,
                composition_path,
                candidate_fn_path,
                environment_config_paths,
                observed_resources_path,
            )

            cmd_prefixes = [
                ["crossplane", "render"],
                ["crossplane", "beta", "render"],
            ]

            for prefix in cmd_prefixes:
                cmd = [*prefix, *base_args]
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
                        f"crossplane render timed out after {timeout_seconds}s"
                    ) from None

                if result.returncode == 0:
                    # Cache the winning combination.
                    _working_render_cmd = prefix
                    _working_functions_variant = variant_key
                    return result.stdout

                stderr = (result.stderr or "").lower()
                if (
                    "unexpected argument render" in stderr
                    or 'unknown command "beta"' in stderr
                    or 'unknown command "render"' in stderr
                ):
                    last_error = result.stderr.strip() or result.stdout.strip()
                    continue

                last_error = result.stderr.strip() or result.stdout.strip() or "unknown error"

        raise LoadError(
            "crossplane render failed: "
            + (last_error or "render command is unavailable in this Crossplane CLI version")
        )
    finally:
        # Only clean up temp files that are NOT in the rewrite cache.
        # Cached rewrite files persist across render calls.
        cached_paths: set[str] = set()
        for host_dev, docker_rt in _functions_rewrite_cache.values():
            if host_dev:
                cached_paths.add(host_dev)
            if docker_rt:
                cached_paths.add(docker_rt)
        for tf in temp_files:
            if tf not in cached_paths:
                Path(tf).unlink(missing_ok=True)


def _build_render_args(
    xr_path: str,
    composition_path: str,
    functions_path: str,
    environment_config_paths: list[str],
    observed_resources_path: str | None,
) -> list[str]:
    """Build the positional + optional args for a crossplane render call."""
    args = [xr_path, composition_path, functions_path]
    for env_path in environment_config_paths:
        args.extend(["-e", env_path])
    if observed_resources_path:
        args.append(f"--observed-resources={observed_resources_path}")
    return args


def _get_functions_variants(
    functions_path: str,
    temp_files: list[str],
) -> list[tuple[str, str]]:
    """Return candidate (variant_key, path) pairs, using cached rewrites.

    The result is deterministic for a given functions_path and only
    performs file I/O and Docker inspect calls on the first invocation.
    """
    is_cached = functions_path in _functions_rewrite_cache
    if is_cached:
        host_dev, docker_rt = _functions_rewrite_cache[functions_path]
    else:
        host_dev = _rewrite_functions_for_host_development(functions_path)
        docker_rt = _rewrite_functions_for_docker_runtime(functions_path)
        _functions_rewrite_cache[functions_path] = (host_dev, docker_rt)

    variants: list[tuple[str, str]] = []
    if host_dev is not None:
        variants.append(("host_dev", host_dev))
        # Only track for cleanup on first creation; cached files persist.
        if not is_cached:
            temp_files.append(host_dev)
    variants.append(("original", functions_path))
    if docker_rt is not None:
        variants.append(("docker_rt", docker_rt))
        if not is_cached:
            temp_files.append(docker_rt)
    return variants


def _resolve_functions_variant(
    functions_path: str,
    variant_key: str,
) -> str:
    """Resolve a cached variant key back to a usable file path.

    Cached rewrite files are NOT added to temp_files because they
    persist across render calls for the lifetime of the process.
    """
    if variant_key == "original":
        return functions_path

    cached = _functions_rewrite_cache.get(functions_path)
    if cached is None:
        # Re-populate cache (shouldn't normally happen).
        host_dev = _rewrite_functions_for_host_development(functions_path)
        docker_rt = _rewrite_functions_for_docker_runtime(functions_path)
        _functions_rewrite_cache[functions_path] = (host_dev, docker_rt)
        cached = (host_dev, docker_rt)

    host_dev, docker_rt = cached
    if variant_key == "host_dev" and host_dev is not None:
        return host_dev
    if variant_key == "docker_rt" and docker_rt is not None:
        return docker_rt

    return functions_path


# Cache for Docker container IPs — looked up once per process.
_container_ip_cache: dict[str, str] = {}

# Cache for functions.yaml rewrite results — avoids re-reading/re-parsing
# the same file and re-calling `docker inspect` on every render.
_functions_rewrite_cache: dict[str, tuple[str | None, str | None]] = {}

# Cache for the working crossplane render command variant.
# After the first successful render we know which command shape works
# ("crossplane render" vs "crossplane beta render") and which functions.yaml
# variant to use.  Subsequent renders skip the other candidates.
_working_render_cmd: list[str] | None = None
_working_functions_variant: str | None = None


def _get_container_ip(container_name: str) -> str | None:
    """Get a Docker container's IP address if it is running.

    Cached per-process so we only call `docker inspect` once per container.
    """
    if container_name in _container_ip_cache:
        cached = _container_ip_cache[container_name]
        return cached if cached else None

    try:
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                container_name,
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        ip = result.stdout.strip()
        if result.returncode == 0 and ip:
            _container_ip_cache[container_name] = ip
            return ip
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    _container_ip_cache[container_name] = ""
    return None


def _rewrite_functions_for_host_development(functions_path: str) -> str | None:
    """Rewrite Development-mode functions.yaml to use host-accessible container IPs.

    When function containers are running on a Docker network, their names
    (e.g. ``function-go-templating:9443``) are not resolvable from the host.
    This function detects running containers, gets their Docker IPs, and
    rewrites the Development target annotations so ``crossplane render``
    on the host can connect directly via gRPC.

    Returns a temp file path if any rewrites were made, otherwise None.
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

        runtime = annotations.get("render.crossplane.io/runtime")
        target = annotations.get("render.crossplane.io/runtime-development-target", "")

        if runtime != "Development" or not target:
            rewritten_docs.append(doc)
            continue

        # Parse target: "container-name:port" → lookup container IP
        parts = target.rsplit(":", 1)
        if len(parts) != 2:
            rewritten_docs.append(doc)
            continue

        container_name, port = parts[0], parts[1]
        ip = _get_container_ip(container_name)
        if not ip:
            rewritten_docs.append(doc)
            continue

        # Rewrite target to use host-accessible IP
        new_target = f"{ip}:{port}"
        annotations["render.crossplane.io/runtime-development-target"] = new_target
        changed = True
        rewritten_docs.append(doc)

    if not changed:
        return None

    with tempfile.NamedTemporaryFile(mode="w", suffix="-hostdev.yaml", delete=False) as temp:
        yaml.safe_dump_all(rewritten_docs, temp, sort_keys=False)
        return temp.name


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
    # Extract all field path expressions from the entire template block
    all_expressions = extract_template_expressions(template)
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
                template_expressions=all_expressions,
            )
        )

    return resources


def _parse_go_template_to_docs(template: str) -> list[dict[str, Any]]:
    """Degraded Go template parser: strips control lines and replaces expressions.

    WARNING: This is a best-effort offline parser that loses template logic.
    It works for simple templates where expressions only appear in YAML values,
    but fails on conditionals that change document structure, ranges that
    create multiple resources, and expressions in YAML-structural positions.

    For accurate results, use crossplane render (render_mode="render" or "auto").
    """
    sanitized_lines: list[str] = []
    for line in template.splitlines():
        stripped = line.strip()
        if _is_go_template_control_line(stripped):
            continue
        sanitized_lines.append(_replace_template_expressions(line))

    sanitized = "\n".join(sanitized_lines)
    docs: list[dict[str, Any]] = []
    try:
        for doc in yaml.safe_load_all(sanitized):
            if isinstance(doc, dict):
                docs.append(doc)
    except yaml.YAMLError:
        # Sanitized template produced invalid YAML — this is expected for
        # complex templates with structural expressions.  Return whatever
        # documents were successfully parsed before the error.
        pass
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


# Regex to extract dot-path expressions from Go templates.
# Matches patterns like: .observed.composite.resource.spec.forProvider.vpcId
# or .spec.parameters.region
_GO_TEMPLATE_DOT_PATH_RE = re.compile(r"\.\w+(?:\.\w+)+")


def extract_template_expressions(template: str) -> list[str]:
    """Extract field path expressions from a Go template string.

    Returns a deduplicated list of dot-paths found in {{ ... }} blocks.
    These are used by L1-07 to validate that template variables reference
    real XRD/CRD fields.
    """
    expressions: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(r"{{([^{}]*)}}", template):
        body = match.group(1).strip()
        # Skip pure control flow
        if body.startswith(("if ", "end", "else", "range ", "with ", "/*", "$")):
            continue
        # Extract dot-paths from the expression body
        for path_match in _GO_TEMPLATE_DOT_PATH_RE.finditer(body):
            path = path_match.group(0).lstrip(".")
            if path not in seen:
                seen.add(path)
                expressions.append(path)
    return expressions


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
