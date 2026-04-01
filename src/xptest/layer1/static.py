"""Layer 1 — Static Validation.

Checks performed (no AWS credentials, no live cluster required):
  L1-01  Schema validation of each composed resource against the local CRD bundle.
  L1-02  Patch field path syntax check (fromFieldPath / toFieldPath must be non-empty strings).
  L1-03  Duplicate composed resource name detection.
  L1-04  Provider lock constraint (apiVersion / kind must exist in the CRD bundle).
  L1-05  Deprecated field detection against known AWS provider deprecated fields.
  L1-06  EnvironmentConfig fixture presence check for FromEnvironmentFieldPath patches.
  L1-07  Go template variable validation for Pipeline-mode compositions.

Execution target: < 5 seconds for typical compositions.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from xptest.cache import CrdBundleCache
from xptest.models import ComposedResource, CompositionObject, Finding, Severity

# A valid Kubernetes/Crossplane field path: dot-separated identifiers.
# Segments may contain hyphens (common in resource names, e.g. "main-vpc").
# Optionally includes array indices e.g. "spec.forProvider.subnets[0].id"
# or array wildcards e.g. "spec.forProvider.tags[*].key"
_FIELD_PATH_RE = re.compile(
    r"^[a-zA-Z_][a-zA-Z0-9_-]*(\[(\d+|\*)\])?(\.[a-zA-Z_][a-zA-Z0-9_-]*(\[(\d+|\*)\])?)*$"
)

# Patch types that carry fromFieldPath / toFieldPath values.
_PATCHTYPES_WITH_PATHS = {
    "FromCompositeFieldPath",
    "ToCompositeFieldPath",
    "CombineFromComposite",
    "FromEnvironmentFieldPath",
}


def run(
    obj: CompositionObject,
    crd_cache: CrdBundleCache | None = None,
) -> list[Finding]:
    """Execute all Layer 1 checks and return findings."""
    findings: list[Finding] = []
    findings.extend(_check_duplicate_names(obj))
    findings.extend(_check_provider_lock(obj, crd_cache))
    findings.extend(_check_patch_field_paths(obj))
    findings.extend(_check_environment_config_present(obj))
    findings.extend(_check_deprecated_fields(obj))
    findings.extend(_check_template_variables(obj, crd_cache))
    if obj.crd_bundle_path:
        findings.extend(_check_schema(obj, crd_cache))
    return findings


# ---------------------------------------------------------------------------
# L1-03 — Duplicate composed resource names
# ---------------------------------------------------------------------------


def _check_duplicate_names(obj: CompositionObject) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for res in obj.resources:
        if res.name in seen:
            findings.append(
                Finding(
                    layer=1,
                    rule="L1-03/duplicate-resource-name",
                    resource=res.name,
                    path="spec.resources[].name",
                    severity=Severity.CRITICAL,
                    message=f"Duplicate composed resource name '{res.name}'. "
                    "Each composed resource must have a unique name within the Composition.",
                    remediation="Rename one of the conflicting composed resources.",
                )
            )
        seen.add(res.name)
    return findings


# ---------------------------------------------------------------------------
# L1-04 — Provider lock: apiVersion + kind must be known in the CRD bundle
# ---------------------------------------------------------------------------


def _check_provider_lock(
    obj: CompositionObject,
    crd_cache: CrdBundleCache | None = None,
) -> list[Finding]:
    if not obj.crd_bundle_path:
        return []

    known = crd_cache.known_kinds if crd_cache else _load_known_kinds(obj.crd_bundle_path)
    findings: list[Finding] = []
    for res in obj.resources:
        key = (res.api_version, res.kind)
        if res.api_version and res.kind and key not in known:
            findings.append(
                Finding(
                    layer=1,
                    rule="L1-04/unknown-provider-kind",
                    resource=res.name,
                    path="base.apiVersion/base.kind",
                    severity=Severity.WARNING,
                    message=(
                        f"'{res.api_version}/{res.kind}' is not present in the CRD bundle "
                        f"at '{obj.crd_bundle_path}'. "
                        "The bundle may be incomplete or the provider version may differ."
                    ),
                    remediation=(
                        "Verify that the CRD bundle path in xptest.yaml matches the "
                        "provider version used in your Composition."
                    ),
                )
            )
    return findings


def _load_known_kinds(bundle_path: str) -> set[tuple[str, str]]:
    """Return a set of (apiVersion, kind) tuples from all CRD files in the bundle."""
    known: set[tuple[str, str]] = set()
    bundle = Path(bundle_path)
    if not bundle.is_dir():
        return known
    for crd_file in bundle.rglob("*.yaml"):
        try:
            with crd_file.open() as fh:
                doc = yaml.safe_load(fh)
            if not isinstance(doc, dict) or doc.get("kind") != "CustomResourceDefinition":
                continue
            spec = doc.get("spec", {})
            group: str = spec.get("group", "")
            names: dict[str, Any] = spec.get("names", {})
            kind: str = names.get("kind", "")
            versions: list[dict[str, Any]] = spec.get("versions", [])
            for v in versions:
                v_name: str = v.get("name", "")
                if group and kind and v_name:
                    known.add((f"{group}/{v_name}", kind))
        except Exception:  # noqa: BLE001
            continue
    return known


# ---------------------------------------------------------------------------
# L1-02 — Patch field path syntax
# ---------------------------------------------------------------------------


def _check_patch_field_paths(obj: CompositionObject) -> list[Finding]:
    findings: list[Finding] = []
    for res in obj.resources:
        for patch in res.patches:
            patch_type: str = patch.get("type", "FromCompositeFieldPath")
            if patch_type not in _PATCHTYPES_WITH_PATHS:
                continue
            for path_key in ("fromFieldPath", "toFieldPath"):
                val = patch.get(path_key)
                if val is None:
                    continue
                if not isinstance(val, str) or not val.strip():
                    findings.append(
                        Finding(
                            layer=1,
                            rule="L1-02/invalid-field-path",
                            resource=res.name,
                            path=f"patches[type={patch_type}].{path_key}",
                            severity=Severity.CRITICAL,
                            message=(
                                f"Patch '{path_key}' in resource '{res.name}' is empty or "
                                "not a string. Every patch field path must be a non-empty "
                                "dot-separated identifier."
                            ),
                            remediation=f"Set a valid dot-path value for '{path_key}'.",
                        )
                    )
                elif not _FIELD_PATH_RE.match(val):
                    findings.append(
                        Finding(
                            layer=1,
                            rule="L1-02/invalid-field-path",
                            resource=res.name,
                            path=f"patches[type={patch_type}].{path_key}",
                            severity=Severity.WARNING,
                            message=(
                                f"Patch '{path_key}' value '{val}' in resource '{res.name}' "
                                "does not match the expected dot-separated identifier format."
                            ),
                            remediation=(
                                "Use a dot-separated field path such as 'spec.forProvider.vpcId'."
                            ),
                        )
                    )
    return findings


# ---------------------------------------------------------------------------
# L1-06 — EnvironmentConfig fixture presence
# ---------------------------------------------------------------------------


def _check_environment_config_present(obj: CompositionObject) -> list[Finding]:
    """Warn when a composition uses FromEnvironmentFieldPath patches but no
    EnvironmentConfig fixture files were supplied.

    Design ref: framework-design.md §3.1, Decision 2.
    """
    uses_env = False
    for res in obj.resources:
        for patch in res.patches:
            patch_type = patch.get("type", "")
            if patch_type == "FromEnvironmentFieldPath":
                uses_env = True
                break
        if uses_env:
            break

    if not uses_env:
        return []

    if obj.environment_config_paths:
        return []

    return [
        Finding(
            layer=1,
            rule="L1-06/environment-config-missing",
            resource="",
            path="patches[type=FromEnvironmentFieldPath]",
            severity=Severity.WARNING,
            message=(
                "Composition uses FromEnvironmentFieldPath patches but no "
                "EnvironmentConfig fixture files were supplied. "
                "Rendered values may be empty or incorrect."
            ),
            remediation=(
                "Supply EnvironmentConfig fixtures via environment_config_paths "
                "in xptest.yaml or the -e flag in crossplane render."
            ),
        )
    ]


# ---------------------------------------------------------------------------
# L1-05 — Deprecated field detection
# ---------------------------------------------------------------------------

# Known deprecated fields per (apiVersion-prefix, kind).
# Keys: (apiVersion prefix, kind, dot-path from spec.forProvider).
# Extended per provider bundle release.
_DEPRECATED_FIELDS: list[tuple[str, str, str, str]] = [
    # AWS provider deprecated fields
    (
        "aws.upbound.io",
        "SecurityGroup",
        "spec.forProvider.ingress",
        "Use SecurityGroupRule resources instead of inline ingress rules.",
    ),
    (
        "aws.upbound.io",
        "SecurityGroup",
        "spec.forProvider.egress",
        "Use SecurityGroupRule resources instead of inline egress rules.",
    ),
    (
        "ec2.aws.upbound.io",
        "SecurityGroup",
        "spec.forProvider.ingress",
        "Use SecurityGroupRule resources instead of inline ingress rules.",
    ),
    (
        "ec2.aws.upbound.io",
        "SecurityGroup",
        "spec.forProvider.egress",
        "Use SecurityGroupRule resources instead of inline egress rules.",
    ),
    (
        "s3.aws.upbound.io",
        "Bucket",
        "spec.forProvider.acl",
        "Use BucketAcl resource instead of inline acl field.",
    ),
    (
        "aws.upbound.io",
        "Bucket",
        "spec.forProvider.acl",
        "Use BucketAcl resource instead of inline acl field.",
    ),
]


def _check_deprecated_fields(obj: CompositionObject) -> list[Finding]:
    """Detect usage of deprecated fields in composed resource specs.

    Design ref: framework-design.md §3.1, L1-05.
    Checks spec.forProvider fields against a known-deprecated registry.
    """
    findings: list[Finding] = []
    for res in obj.resources:
        for api_prefix, kind, field_path, remedy in _DEPRECATED_FIELDS:
            if not res.api_version.startswith(api_prefix):
                continue
            if res.kind != kind:
                continue
            # Navigate the dot-path to check if field is present
            if _field_exists(res.spec, field_path.removeprefix("spec.")):
                findings.append(
                    Finding(
                        layer=1,
                        rule="L1-05/deprecated-field",
                        resource=res.name,
                        path=field_path,
                        severity=Severity.WARNING,
                        message=(
                            f"Resource '{res.name}' ({res.api_version}/{res.kind}) "
                            f"uses deprecated field '{field_path}'."
                        ),
                        remediation=remedy,
                    )
                )
    return findings


def _field_exists(spec: dict[str, Any], dot_path: str) -> bool:
    """Check if a dot-separated path exists in a nested dict."""
    parts = dot_path.split(".")
    current: Any = spec
    for part in parts:
        if not isinstance(current, dict):
            return False
        if part not in current:
            return False
        current = current[part]
    return True


# ---------------------------------------------------------------------------
# L1-07 — Go template variable validation
# ---------------------------------------------------------------------------

# Known root prefixes in Crossplane Go templates
_KNOWN_TEMPLATE_ROOTS = {
    "observed",
    "desired",
    "spec",
    "metadata",
    "status",
}

# Sub-paths under observed.composite.resource that should exist
_OBSERVED_COMPOSITE_PREFIXES = ("observed.composite.resource.",)


def _check_template_variables(
    obj: CompositionObject,
    crd_cache: CrdBundleCache | None = None,
) -> list[Finding]:
    """Validate Go template expressions reference known field paths.

    For Pipeline-mode compositions using function-go-templating, checks that:
    1. Template expressions use known root objects (observed, desired, spec, etc.)
    2. Field paths under observed.composite.resource.spec match XRD parameters
    """
    findings: list[Finding] = []
    xrd_params = _extract_xrd_param_names(obj.xrd_spec)

    for res in obj.resources:
        if not res.template_expressions:
            continue

        for expr in res.template_expressions:
            parts = expr.split(".")

            # Check 1: unknown root object
            if parts[0] not in _KNOWN_TEMPLATE_ROOTS:
                findings.append(
                    Finding(
                        layer=1,
                        rule="L1-07/unknown-template-root",
                        resource=res.name,
                        path=f"template.{expr}",
                        severity=Severity.WARNING,
                        message=(
                            f"Template expression '.{expr}' in resource "
                            f"'{res.name}' uses unknown root '{parts[0]}'. "
                            "Expected one of: observed, desired, spec, "
                            "metadata, status."
                        ),
                        remediation=(
                            "Verify the template variable references a "
                            "valid Crossplane context object."
                        ),
                    )
                )

            # Check 2: observed.composite.resource.spec.X — validate X against XRD
            if xrd_params and expr.startswith("observed.composite.resource.spec."):
                spec_path = expr.removeprefix("observed.composite.resource.spec.")
                top_field = spec_path.split(".")[0]
                if top_field and top_field not in xrd_params:
                    findings.append(
                        Finding(
                            layer=1,
                            rule="L1-07/unknown-xrd-parameter",
                            resource=res.name,
                            path=f"template.{expr}",
                            severity=Severity.WARNING,
                            message=(
                                f"Template expression '.{expr}' in resource "
                                f"'{res.name}' references XRD parameter "
                                f"'{top_field}' which is not declared in the "
                                "XRD spec schema."
                            ),
                            remediation=(
                                f"Add '{top_field}' to the XRD "
                                "openAPIV3Schema or fix the template "
                                "variable name."
                            ),
                        )
                    )

    return findings


def _extract_xrd_param_names(xrd_spec: dict[str, Any]) -> set[str]:
    """Extract top-level parameter names from XRD openAPIV3Schema."""
    versions = xrd_spec.get("versions", [])
    if not versions:
        return set()
    schema = (
        versions[0]
        .get("schema", {})
        .get("openAPIV3Schema", {})
        .get("properties", {})
        .get("spec", {})
        .get("properties", {})
    )
    return set(schema.keys()) if schema else set()


# ---------------------------------------------------------------------------
# L1-01 — Schema validation against CRD bundle
# ---------------------------------------------------------------------------


def _check_schema(
    obj: CompositionObject,
    crd_cache: CrdBundleCache | None = None,
) -> list[Finding]:
    """Validate each composed resource's spec against its CRD schema."""
    try:
        import jsonschema  # noqa: PLC0415
    except ImportError:
        return []  # jsonschema not installed; skip silently

    if crd_cache:
        crd_map = crd_cache.crd_schemas
    else:
        bundle = Path(obj.crd_bundle_path)
        if not bundle.is_dir():
            return []
        crd_map = _build_crd_map(bundle)
    findings: list[Finding] = []

    for res in obj.resources:
        schema = _resolve_schema(crd_map, res)
        if schema is None:
            continue
        instance = {"spec": res.spec}
        try:
            jsonschema.validate(instance=instance, schema=schema)
        except jsonschema.ValidationError as exc:
            path_str = ".".join(str(p) for p in exc.absolute_path) or "spec"
            findings.append(
                Finding(
                    layer=1,
                    rule="L1-01/schema-violation",
                    resource=res.name,
                    path=path_str,
                    severity=Severity.CRITICAL,
                    message=(
                        f"Schema validation failed for '{res.name}' "
                        f"({res.api_version}/{res.kind}): {exc.message}"
                    ),
                    remediation=(
                        "Review the field against the CRD schema for "
                        f"'{res.kind}' in the CRD bundle."
                    ),
                )
            )
        except jsonschema.SchemaError:
            pass  # malformed CRD schema; skip this resource

    return findings


def _build_crd_map(
    bundle: Path,
) -> dict[tuple[str, str], dict[str, Any]]:
    """Return a map of (apiVersion, kind) -> openAPIV3Schema for validation."""
    crd_map: dict[tuple[str, str], dict[str, Any]] = {}
    for crd_file in bundle.rglob("*.yaml"):
        try:
            with crd_file.open() as fh:
                doc = yaml.safe_load(fh)
            if not isinstance(doc, dict) or doc.get("kind") != "CustomResourceDefinition":
                continue
            spec = doc.get("spec", {})
            group: str = spec.get("group", "")
            kind: str = spec.get("names", {}).get("kind", "")
            for v in spec.get("versions", []):
                v_name: str = v.get("name", "")
                schema_block = v.get("schema", {}).get("openAPIV3Schema", {})
                if group and kind and v_name and schema_block:
                    crd_map[(f"{group}/{v_name}", kind)] = schema_block
        except Exception:  # noqa: BLE001
            continue
    return crd_map


def _resolve_schema(
    crd_map: dict[tuple[str, str], dict[str, Any]],
    res: ComposedResource,
) -> dict[str, Any] | None:
    """Return the openAPIV3Schema for this resource, or None if not found."""
    key = (res.api_version, res.kind)
    schema = crd_map.get(key)
    if schema is None:
        return None
    # Return only the spec sub-schema wrapped so jsonschema can validate {"spec": ...}
    spec_schema = schema.get("properties", {}).get("spec")
    if spec_schema is None:
        return None
    return {"type": "object", "properties": {"spec": spec_schema}}
