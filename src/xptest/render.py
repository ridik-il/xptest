"""Render pipeline-mode Crossplane compositions through real function execution.

When a composition uses function-go-templating, the only reliable way to
obtain the composed resources is to execute the template through the actual
function.  This module handles:

  1. Auto-generating a minimal XR claim from XRD schema
  2. Auto-generating functions.yaml from composition pipeline steps
  3. Executing ``crossplane render`` (which manages Docker containers)
  4. Parsing the rendered output into ComposedResource objects

The Crossplane CLI's ``render`` command pulls and runs function images as
Docker containers automatically.  No manual Docker lifecycle management is
needed — the CLI handles container start, gRPC communication, and cleanup.

If the Crossplane CLI or Docker is unavailable, callers should fall back to
degraded offline parsing.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml


class RenderError(RuntimeError):
    """Raised when crossplane render fails with an actionable error."""

    def __init__(self, message: str, stderr: str = "", stdout: str = "") -> None:
        super().__init__(message)
        self.stderr = stderr
        self.stdout = stdout


class RenderUnavailable(RuntimeError):
    """Raised when rendering infrastructure is not present (no CLI, no Docker)."""


# Well-known Crossplane function images.
# These are used when no functions.yaml is provided — we infer images from
# the composition's pipeline step functionRef names.
_WELL_KNOWN_FUNCTIONS: dict[str, str] = {
    "function-go-templating": ("xpkg.upbound.io/crossplane-contrib/function-go-templating:v0.7.0"),
    "function-auto-ready": ("xpkg.upbound.io/crossplane-contrib/function-auto-ready:v0.3.0"),
    "function-environment-configs": (
        "xpkg.upbound.io/crossplane-contrib/function-environment-configs:v0.1.0"
    ),
    "function-patch-and-transform": (
        "xpkg.upbound.io/crossplane-contrib/function-patch-and-transform:v0.8.0"
    ),
    "function-kcl": ("xpkg.upbound.io/crossplane-contrib/function-kcl:v0.9.0"),
}


def crossplane_cli_available() -> bool:
    """Return True if the crossplane CLI is on PATH."""
    try:
        result = subprocess.run(
            ["crossplane", "version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def generate_xr_from_xrd(
    xrd_doc: dict[str, Any],
    composition_doc: dict[str, Any],
) -> dict[str, Any]:
    """Generate a minimal XR (composite resource) from an XRD schema.

    Produces a YAML document with:
      - apiVersion from XRD group + first version name
      - kind from XRD names.kind
      - metadata with a stable test name and common labels
      - spec with required fields filled using type-appropriate defaults

    This XR is sufficient for ``crossplane render`` to execute the pipeline.
    """
    xrd_spec = xrd_doc.get("spec", {})
    group = xrd_spec.get("group", "example.org")
    names = xrd_spec.get("names", {})
    kind = names.get("kind", "XResource")
    versions = xrd_spec.get("versions", [])
    version_name = versions[0].get("name", "v1alpha1") if versions else "v1alpha1"

    # Use composite type ref from composition if available
    comp_spec = composition_doc.get("spec", {})
    type_ref = comp_spec.get("compositeTypeRef", {})
    api_version = type_ref.get("apiVersion", f"{group}/{version_name}")
    ref_kind = type_ref.get("kind", kind)

    # Extract spec schema to generate defaults for required fields
    spec_schema: dict[str, Any] = {}
    if versions:
        spec_schema = (
            versions[0]
            .get("schema", {})
            .get("openAPIV3Schema", {})
            .get("properties", {})
            .get("spec", {})
        )

    spec_defaults = _generate_spec_defaults(spec_schema)

    xr: dict[str, Any] = {
        "apiVersion": api_version,
        "kind": ref_kind,
        "metadata": {
            "name": "xptest-render",
            "labels": {
                "crossplane.io/claim-name": "xptest-render",
                "crossplane.io/claim-namespace": "default",
                "crossplane.io/composite": "xptest-render",
            },
        },
        "spec": spec_defaults,
    }

    return xr


def _generate_spec_defaults(
    spec_schema: dict[str, Any],
) -> dict[str, Any]:
    """Generate default values for XRD spec fields.

    For required fields: fill with type-appropriate defaults.
    For optional fields with defaults: use the default.
    For other optional fields: include with sensible defaults so templates
    that reference them don't produce nil errors.
    """
    properties = dict(spec_schema.get("properties", {}))

    # Merge properties from allOf/oneOf branches so nested required fields
    # are discovered and populated with defaults.
    for constraint in spec_schema.get("allOf", []):
        for k, v in constraint.get("properties", {}).items():
            properties.setdefault(k, v)
    for constraint in spec_schema.get("oneOf", [])[:1]:
        for k, v in constraint.get("properties", {}).items():
            properties.setdefault(k, v)

    defaults: dict[str, Any] = {}

    for name, prop in properties.items():
        prop_type = prop.get("type", "string")
        default = prop.get("default")
        enum = prop.get("enum")

        if default is not None:
            defaults[name] = default
        elif enum:
            defaults[name] = enum[0]
        elif prop_type == "string":
            defaults[name] = _string_default(name, prop)
        elif prop_type == "integer":
            defaults[name] = prop.get("minimum", 1)
        elif prop_type == "number":
            defaults[name] = prop.get("minimum", 1.0)
        elif prop_type == "boolean":
            defaults[name] = False
        elif prop_type == "array":
            # Include empty array — templates must handle this
            defaults[name] = []
        elif prop_type == "object":
            # Recurse into nested objects
            nested = _generate_spec_defaults(prop)
            defaults[name] = nested if nested else {}
        else:
            defaults[name] = f"xptest-{name}"

    return defaults


def _string_default(name: str, prop: dict[str, Any]) -> str:
    """Generate a sensible string default based on field name patterns."""
    lower = name.lower()
    if "region" in lower:
        return "us-east-1"
    if "namespace" in lower:
        return "default"
    if "name" in lower:
        return f"xptest-{name}"
    if "arn" in lower:
        return "arn:aws:iam::123456789012:role/xptest-placeholder"
    if "id" in lower:
        return "xptest-id"
    min_len = prop.get("minLength", 0)
    return f"xptest-{name}" if min_len <= 20 else "x" * min_len


def generate_functions_yaml(
    composition_doc: dict[str, Any],
) -> list[dict[str, Any]]:
    """Generate functions.yaml documents from a composition's pipeline steps.

    Each pipeline step with a functionRef is mapped to a Function resource
    using well-known images.  Unknown functions are included with a
    placeholder package so crossplane render can report the error clearly.
    """
    spec = composition_doc.get("spec", {})
    pipeline = spec.get("pipeline", [])

    seen: set[str] = set()
    functions: list[dict[str, Any]] = []

    for step in pipeline:
        func_ref = step.get("functionRef", {})
        func_name = func_ref.get("name", "")
        if not func_name or func_name in seen:
            continue
        seen.add(func_name)

        package = _WELL_KNOWN_FUNCTIONS.get(
            func_name,
            f"xpkg.upbound.io/unknown/{func_name}:latest",
        )

        functions.append(
            {
                "apiVersion": "pkg.crossplane.io/v1beta1",
                "kind": "Function",
                "metadata": {"name": func_name},
                "spec": {"package": package},
            }
        )

    return functions


def has_go_templating_steps(composition_doc: dict[str, Any]) -> bool:
    """Return True if the composition has any pipeline step using GoTemplate."""
    spec = composition_doc.get("spec", {})
    for step in spec.get("pipeline", []):
        step_input = step.get("input", {})
        if step_input.get("kind") == "GoTemplate":
            return True
        # Also check function name pattern
        func_name = step.get("functionRef", {}).get("name", "")
        if "go-templating" in func_name:
            return True
    return False


def render_composition(
    composition_path: str,
    xr_yaml: str,
    functions_yaml: str,
    environment_config_paths: list[str] | None = None,
    observed_resources_path: str | None = None,
    timeout: int = 120,
) -> str:
    """Execute crossplane render and return the raw YAML output.

    Args:
        composition_path: Path to the Composition YAML file.
        xr_yaml: YAML string for the XR claim document.
        functions_yaml: YAML string for functions definitions.
        environment_config_paths: Optional EnvironmentConfig file paths.
        observed_resources_path: Optional observed resources file path.
        timeout: Subprocess timeout in seconds.

    Returns:
        Raw multi-document YAML string from crossplane render.

    Raises:
        RenderUnavailable: If crossplane CLI is not found.
        RenderError: If rendering fails with an error.
    """
    # Write temporary files for XR and functions
    xr_file = tempfile.NamedTemporaryFile(mode="w", suffix="-xr.yaml", delete=False)
    functions_file = tempfile.NamedTemporaryFile(mode="w", suffix="-functions.yaml", delete=False)

    try:
        xr_file.write(xr_yaml)
        xr_file.close()
        functions_file.write(functions_yaml)
        functions_file.close()

        args = [xr_file.name, composition_path, functions_file.name]

        if environment_config_paths:
            for env_path in environment_config_paths:
                args.extend(["-e", env_path])

        if observed_resources_path:
            args.append(f"--observed-resources={observed_resources_path}")

        # Try both command variants
        commands = [
            ["crossplane", "render", *args],
            ["crossplane", "beta", "render", *args],
        ]

        last_error = ""
        for cmd in commands:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            except FileNotFoundError:
                raise RenderUnavailable("crossplane CLI not found on PATH") from None
            except subprocess.TimeoutExpired:
                raise RenderError(f"crossplane render timed out after {timeout}s") from None

            if result.returncode == 0:
                return result.stdout

            stderr = (result.stderr or "").lower()
            # Skip version-incompatible command variants
            if any(
                msg in stderr
                for msg in [
                    "unknown command",
                    "unexpected argument",
                ]
            ):
                last_error = result.stderr.strip()
                continue

            # Real render failure — report it
            raise RenderError(
                f"crossplane render failed (exit {result.returncode})",
                stderr=result.stderr.strip(),
                stdout=result.stdout.strip(),
            )

        raise RenderUnavailable(f"crossplane render command not available: {last_error}")

    finally:
        Path(xr_file.name).unlink(missing_ok=True)
        Path(functions_file.name).unlink(missing_ok=True)


def auto_render_pipeline(
    composition_path: str,
    xrd_path: str,
    functions_path: str | None = None,
    environment_config_paths: list[str] | None = None,
    observed_resources_path: str | None = None,
    timeout: int = 120,
) -> str:
    """Render a pipeline composition with auto-generated inputs.

    Generates a minimal XR and functions.yaml if not provided,
    then executes crossplane render.

    Returns raw rendered YAML string.
    """
    comp_doc = _read_yaml_doc(composition_path)
    xrd_doc = _read_yaml_doc(xrd_path)

    # Generate XR
    xr_doc = generate_xr_from_xrd(xrd_doc, comp_doc)
    xr_yaml = yaml.dump(xr_doc, default_flow_style=False)

    # Generate or read functions.yaml
    if functions_path and Path(functions_path).exists():
        functions_yaml = Path(functions_path).read_text()
    else:
        func_docs = generate_functions_yaml(comp_doc)
        if not func_docs:
            raise RenderError("No pipeline steps found in composition")
        functions_yaml = yaml.dump_all(func_docs, default_flow_style=False)

    return render_composition(
        composition_path=composition_path,
        xr_yaml=xr_yaml,
        functions_yaml=functions_yaml,
        environment_config_paths=environment_config_paths,
        observed_resources_path=observed_resources_path,
        timeout=timeout,
    )


def _read_yaml_doc(path: str) -> dict[str, Any]:
    """Read a single YAML document from a file."""
    with Path(path).open() as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict):
        raise RenderError(f"{path}: expected YAML mapping")
    return doc
