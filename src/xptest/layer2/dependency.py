"""Layer 2 — Dependency Validation.

Checks performed (no AWS credentials, no live cluster required):
  L2-01  Reference completeness: every edge's source atProvider field must exist
         in the CRD bundle's status.atProvider schema.
  L2-02  Cycle detection in the resource dependency graph.
  L2-03  Dangling reference: a patch reads from a resource name not present in
         the composition.
  L2-04  Missing readiness gate: a resource that is a dependency producer has no
         readinessCheck defined.
  L2-05  Cross-composition ordering: validate dependency manifest declaring
         explicit inter-composition edges (Decision 6).
  L2-06  Ineffective readiness check: a readinessCheck uses a field path that
         is always present (e.g. metadata.name), making the check a no-op.

Edge-creating patch types (confirmed U3):
  - FromCompositeFieldPath   — when fromFieldPath starts with "status.atProvider."
                               of another composed resource
  - CombineFromComposite     — when any combine source starts with "status.atProvider."
  - matchLabels selectors    — a composed resource's forProvider contains a selector
                               block with matchLabels or matchControllerRef

Execution target: < 10 seconds for typical compositions.
"""

from __future__ import annotations

import graphlib
from pathlib import Path
from typing import Any

import yaml

from xptest.cache import CrdBundleCache
from xptest.models import CompositionObject, Finding, Severity


def run(
    obj: CompositionObject,
    crd_cache: CrdBundleCache | None = None,
) -> list[Finding]:
    """Execute all Layer 2 checks and return findings."""
    resource_names = {r.name for r in obj.resources}
    # resolved_edges: edges where producer IS a known resource (used for cycle and readiness)
    # candidate_refs: all (producer_name, consumer_name) pairs extracted from patches,
    #                 including unresolved names (used for dangling reference detection)
    resolved_edges, candidate_refs = _extract_edges(obj)

    findings: list[Finding] = []
    findings.extend(_check_dangling_references(candidate_refs, resource_names, obj))
    findings.extend(_check_cycles(resolved_edges, obj))
    findings.extend(_check_missing_readiness_gates(resolved_edges, obj))
    findings.extend(_check_ineffective_readiness(obj))
    if obj.crd_bundle_path:
        findings.extend(_check_reference_completeness(obj, crd_cache))
    return findings


# ---------------------------------------------------------------------------
# Edge extraction
# ---------------------------------------------------------------------------


def _extract_edges(
    obj: CompositionObject,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Return two lists of (producer_name, consumer_name) pairs.

    resolved_edges: only pairs where producer IS a known resource in this
        Composition.  Used for cycle detection and readiness gate checks.

    candidate_refs: ALL pairs extracted from patches, including pairs where
        the producer name is unknown.  Used for dangling reference detection.

    An edge means: consumer depends on producer — consumer must wait for
    producer to be ready before its own patch fields can be resolved.
    """
    resource_index = {r.name: r for r in obj.resources}
    resolved_edges: list[tuple[str, str]] = []
    candidate_refs: list[tuple[str, str]] = []

    for consumer in obj.resources:
        # --- FromCompositeFieldPath / CombineFromComposite patches ---
        for patch in consumer.patches:
            patch_type = patch.get("type", "FromCompositeFieldPath")
            if patch_type == "FromCompositeFieldPath":
                from_path: str = patch.get("fromFieldPath", "")
                producer = _resolve_atprovider_producer(from_path)
                if producer and producer != consumer.name:
                    candidate_refs.append((producer, consumer.name))
                    if producer in resource_index:
                        resolved_edges.append((producer, consumer.name))

            elif patch_type == "CombineFromComposite":
                combine: dict[str, Any] = patch.get("combine", {})
                for var in combine.get("variables", []):
                    from_path = var.get("fromFieldPath", "")
                    producer = _resolve_atprovider_producer(from_path)
                    if producer and producer != consumer.name:
                        candidate_refs.append((producer, consumer.name))
                        if producer in resource_index:
                            resolved_edges.append((producer, consumer.name))

        # --- Selector references (matchLabels / matchControllerRef) ---
        if consumer.selector is not None:
            labels: dict[str, str] = consumer.selector.get("matchLabels", {})
            for candidate in obj.resources:
                if candidate.name == consumer.name:
                    continue
                if _selector_matches(labels, candidate):
                    resolved_edges.append((candidate.name, consumer.name))
                    candidate_refs.append((candidate.name, consumer.name))

    return resolved_edges, candidate_refs


def _resolve_atprovider_producer(from_path: str) -> str | None:
    """If from_path uses the cross-resource convention, return the referenced resource name.

    The convention used in these fixtures and compositions is:
        status.atProvider.<resourceName>.<field>

    where <resourceName> is the name of another composed resource in the same
    Composition.  This pattern occurs when an author writes a ToCompositeFieldPath
    on the producer to surface the atProvider field onto the XR composite status,
    and a FromCompositeFieldPath on the consumer to read it back.

    A path with only three segments (status.atProvider.<field>) refers to the
    XR's own status and does not create a cross-resource dependency edge.

    The returned name may or may not exist in resource_index — a missing name
    is reported as a dangling reference by L2-03.
    """
    parts = from_path.split(".")
    # Must have at least 4 segments: status . atProvider . <resourceName> . <field>
    if (
        len(parts) >= 4
        and parts[0] == "status"
        and parts[1] == "atProvider"
        and parts[2]  # non-empty resource name segment
    ):
        return parts[2]

    return None


def _selector_matches(
    labels: dict[str, str],
    candidate: Any,  # ComposedResource
) -> bool:
    """Return True if the selector label map could match the candidate resource."""
    # In Crossplane, a composed resource is selected by a label that typically
    # encodes the composition-resource-name.  We check whether the candidate's
    # name appears as a value in the matchLabels dict.
    if not labels:
        return False
    return candidate.name in labels.values()


# ---------------------------------------------------------------------------
# L2-03 — Dangling references
# ---------------------------------------------------------------------------


def _check_dangling_references(
    edges: list[tuple[str, str]],
    resource_names: set[str],
    obj: CompositionObject,
) -> list[Finding]:
    findings: list[Finding] = []
    for producer, consumer in edges:
        if producer not in resource_names:
            findings.append(
                Finding(
                    layer=2,
                    rule="L2-03/dangling-reference",
                    resource=consumer,
                    path="patches[].fromFieldPath",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Resource '{consumer}' references '{producer}' which does not "
                        "exist in this Composition. The reference will fail to resolve "
                        "during reconciliation."
                    ),
                    remediation=(
                        f"Add a composed resource named '{producer}' to the Composition, "
                        "or correct the field path in the patch."
                    ),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# L2-02 — Cycle detection
# ---------------------------------------------------------------------------


def _check_cycles(
    edges: list[tuple[str, str]],
    obj: CompositionObject,
) -> list[Finding]:
    """Detect cycles using graphlib.TopologicalSorter."""
    graph: dict[str, set[str]] = {r.name: set() for r in obj.resources}
    for producer, consumer in edges:
        if producer in graph and consumer in graph:
            graph[consumer].add(producer)  # consumer depends on producer

    try:
        ts = graphlib.TopologicalSorter(graph)
        list(ts.static_order())
        return []
    except graphlib.CycleError as exc:
        try:
            cycle_nodes = list(exc.args[1]) if len(exc.args) > 1 else []
        except (TypeError, IndexError):
            cycle_nodes = []
        cycle_str = " -> ".join(str(n) for n in cycle_nodes) if cycle_nodes else str(exc)
        return [
            Finding(
                layer=2,
                rule="L2-02/dependency-cycle",
                resource=", ".join(str(n) for n in cycle_nodes),
                path="patches[].fromFieldPath",
                severity=Severity.CRITICAL,
                message=(
                    f"A dependency cycle was detected among composed resources: {cycle_str}. "
                    "Crossplane cannot determine a valid reconciliation order."
                ),
                remediation=(
                    "Remove the circular dependency by restructuring the composition "
                    "or removing one of the cross-resource patch references."
                ),
            )
        ]


# ---------------------------------------------------------------------------
# L2-04 — Missing readiness gate
# ---------------------------------------------------------------------------


def _check_missing_readiness_gates(
    edges: list[tuple[str, str]],
    obj: CompositionObject,
) -> list[Finding]:
    """Warn when a producer resource has no readinessCheck defined.

    Without a readinessCheck, Crossplane considers the resource ready as soon
    as the managed resource object is created, not when the cloud resource is
    actually provisioned.  A downstream consumer that reads atProvider fields
    may receive empty values if the producer is not truly ready.
    """
    producers: set[str] = {producer for producer, _consumer in edges}
    resource_index = {r.name: r for r in obj.resources}
    findings: list[Finding] = []

    for producer_name in producers:
        res = resource_index.get(producer_name)
        if res is None:
            continue
        if not res.readiness_checks:
            findings.append(
                Finding(
                    layer=2,
                    rule="L2-04/missing-readiness-gate",
                    resource=producer_name,
                    path="readinessChecks",
                    severity=Severity.WARNING,
                    message=(
                        f"Resource '{producer_name}' is a dependency producer but has no "
                        "readinessChecks defined. Downstream resources may read empty "
                        "atProvider fields if this resource is not yet fully provisioned."
                    ),
                    remediation=(
                        f"Add a readinessCheck to '{producer_name}', for example: "
                        "readinessChecks: [{type: MatchTrue, fieldPath: "
                        "status.atProvider.id}]"
                    ),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# L2-06 — Ineffective readiness check (always-true field path)
# ---------------------------------------------------------------------------

# Field paths that are populated immediately on resource creation and therefore
# do not indicate actual cloud-resource readiness.
_ALWAYS_PRESENT_FIELDS = {
    "metadata.name",
    "metadata.uid",
    "metadata.resourceVersion",
    "metadata.creationTimestamp",
    "metadata.generation",
    "metadata.namespace",
}


def _check_ineffective_readiness(
    obj: CompositionObject,
) -> list[Finding]:
    """Flag readiness checks that use always-present fields.

    A NonEmpty check on ``metadata.name`` is effectively a no-op: the field is
    populated the moment the Kubernetes object is created, long before the
    cloud resource is actually provisioned.  Downstream consumers that depend
    on ``status.atProvider.*`` fields will read empty values.
    """
    findings: list[Finding] = []
    for res in obj.resources:
        for rc in res.readiness_checks:
            fp = rc.get("fieldPath", "")
            if rc.get("type") == "NonEmpty" and fp in _ALWAYS_PRESENT_FIELDS:
                findings.append(
                    Finding(
                        layer=2,
                        rule="L2-06/ineffective-readiness-check",
                        resource=res.name,
                        path="readinessChecks[].fieldPath",
                        severity=Severity.WARNING,
                        message=(
                            f"Resource '{res.name}' has a readinessCheck on "
                            f"'{fp}' which is always present on any Kubernetes "
                            f"object. This check does not verify that the cloud "
                            f"resource is actually provisioned."
                        ),
                        remediation=(
                            "Change the readinessCheck fieldPath to a field "
                            "that indicates actual readiness, such as "
                            "'status.atProvider.id' or "
                            "'status.atProvider.endpoint'."
                        ),
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# L2-01 — Reference completeness via CRD bundle status.atProvider schema
# ---------------------------------------------------------------------------


def _check_reference_completeness(
    obj: CompositionObject,
    crd_cache: CrdBundleCache | None = None,
) -> list[Finding]:
    """Check that atProvider fields referenced in patches exist in the CRD bundle.

    For each FromCompositeFieldPath or CombineFromComposite patch that reads
    from a path like "status.atProvider.<resourceName>.<field>", verify that
    <field> exists in the producer resource's CRD status.atProvider schema.
    """
    if crd_cache:
        atprovider_schemas = crd_cache.atprovider_schemas
    else:
        bundle = Path(obj.crd_bundle_path)
        if not bundle.is_dir():
            return []
        atprovider_schemas = _load_atprovider_schemas(bundle)
    resource_index = {r.name: r for r in obj.resources}
    findings: list[Finding] = []

    for consumer in obj.resources:
        for patch in consumer.patches:
            patch_type = patch.get("type", "FromCompositeFieldPath")
            paths_to_check: list[str] = []

            if patch_type == "FromCompositeFieldPath":
                fp = patch.get("fromFieldPath", "")
                if fp:
                    paths_to_check.append(fp)
            elif patch_type == "CombineFromComposite":
                for var in patch.get("combine", {}).get("variables", []):
                    fp = var.get("fromFieldPath", "")
                    if fp:
                        paths_to_check.append(fp)

            for fp in paths_to_check:
                parts = fp.split(".")
                # Expect: status.atProvider.<resourceName>.<field>[.<nested>...]
                if len(parts) < 4:
                    continue
                if parts[0] != "status" or parts[1] != "atProvider":
                    continue
                producer_name = parts[2]
                producer = resource_index.get(producer_name)
                if producer is None:
                    continue  # dangling reference; handled by L2-03
                key = (producer.api_version, producer.kind)
                schema_props = atprovider_schemas.get(key)
                if schema_props is None:
                    continue  # CRD not in bundle; skip
                bad_segment = _walk_schema_path(schema_props, parts[3:])
                if bad_segment is not None:
                    findings.append(
                        Finding(
                            layer=2,
                            rule="L2-01/unknown-atprovider-field",
                            resource=consumer.name,
                            path=f"patches[fromFieldPath={fp}]",
                            severity=Severity.CRITICAL,
                            message=(
                                f"Field '{bad_segment}' is not present in "
                                f"status.atProvider of '{producer.kind}' "
                                f"({producer.api_version}) according to the CRD bundle. "
                                f"Patch in '{consumer.name}' references this field."
                            ),
                            remediation=(
                                f"Verify the correct atProvider field name for "
                                f"'{producer.kind}' in the CRD bundle at "
                                f"'{obj.crd_bundle_path}'."
                            ),
                        )
                    )
    return findings


def _walk_schema_path(
    properties: dict[str, Any],
    segments: list[str],
) -> str | None:
    """Walk nested schema properties along *segments*.

    Returns the first segment that does not exist in the schema, or None
    if every segment resolves successfully.  Stops descending when a
    schema node has no nested ``properties`` (e.g. a scalar leaf).
    """
    current = properties
    for seg in segments:
        if seg not in current:
            return seg
        # Descend into nested properties if they exist
        nested = current[seg].get("properties") if isinstance(current[seg], dict) else None
        if nested is None:
            break  # leaf — remaining segments cannot be validated
        current = nested
    return None


def _load_atprovider_schemas(bundle: Path) -> dict[tuple[str, str], dict[str, Any]]:
    """Return a map of (apiVersion, kind) -> atProvider properties dict."""
    result: dict[tuple[str, str], dict[str, Any]] = {}
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
                open_api = v.get("schema", {}).get("openAPIV3Schema", {})
                at_provider_props = (
                    open_api.get("properties", {})
                    .get("status", {})
                    .get("properties", {})
                    .get("atProvider", {})
                    .get("properties", {})
                )
                if group and kind and v_name and at_provider_props:
                    result[(f"{group}/{v_name}", kind)] = at_provider_props
        except Exception:  # noqa: BLE001
            continue
    return result


# ---------------------------------------------------------------------------
# L2-05 — Cross-composition ordering (Decision 6)
# ---------------------------------------------------------------------------


def check_cross_composition_ordering(
    manifest_path: str,
) -> list[Finding]:
    """Validate a dependency manifest that declares cross-composition edges.

    Manifest YAML structure:
        compositions:
          - name: network-comp
            provides:
              - vpc-id
              - subnet-ids
          - name: database-comp
            depends_on:
              - network-comp
            consumes:
              - vpc-id
              - subnet-ids

    Checks:
      - Every depends_on target must exist as a composition name.
      - Every consumed output must be provided by a declared dependency.
      - No cycles in the cross-composition dependency graph.
    """
    p = Path(manifest_path)
    if not p.exists():
        return []

    try:
        with p.open() as fh:
            doc = yaml.safe_load(fh)
    except Exception:  # noqa: BLE001
        return [
            Finding(
                layer=2,
                rule="L2-05/manifest-parse-error",
                resource="",
                path=manifest_path,
                severity=Severity.CRITICAL,
                message=f"Failed to parse dependency manifest at '{manifest_path}'.",
                remediation="Ensure the manifest is valid YAML.",
            )
        ]

    if not isinstance(doc, dict):
        return []

    compositions: list[dict[str, Any]] = doc.get("compositions", [])
    if not compositions:
        return []

    findings: list[Finding] = []
    known_names: set[str] = set()
    provides_map: dict[str, set[str]] = {}

    for comp in compositions:
        name = comp.get("name", "")
        if name:
            known_names.add(name)
            provides_map[name] = set(comp.get("provides", []))

    # Check depends_on references and consumed outputs
    graph: dict[str, set[str]] = {name: set() for name in known_names}
    for comp in compositions:
        comp_name = comp.get("name", "")
        depends_on: list[str] = comp.get("depends_on", [])
        consumes: list[str] = comp.get("consumes", [])

        for dep in depends_on:
            if dep not in known_names:
                findings.append(
                    Finding(
                        layer=2,
                        rule="L2-05/unknown-composition-dependency",
                        resource=comp_name,
                        path=f"depends_on[{dep}]",
                        severity=Severity.CRITICAL,
                        message=(
                            f"Composition '{comp_name}' depends on '{dep}' "
                            "which is not declared in the dependency manifest."
                        ),
                        remediation="Add the missing composition to the manifest.",
                    )
                )
            else:
                graph.setdefault(comp_name, set()).add(dep)

        for consumed in consumes:
            # Check that at least one dependency provides this output
            provided_by_deps = False
            for dep in depends_on:
                if dep in provides_map and consumed in provides_map[dep]:
                    provided_by_deps = True
                    break
            if not provided_by_deps:
                findings.append(
                    Finding(
                        layer=2,
                        rule="L2-05/unresolved-cross-composition-output",
                        resource=comp_name,
                        path=f"consumes[{consumed}]",
                        severity=Severity.WARNING,
                        message=(
                            f"Composition '{comp_name}' consumes output '{consumed}' "
                            "but no declared dependency provides it."
                        ),
                        remediation=(
                            "Add the providing composition to depends_on "
                            "or add the output to the provider's provides list."
                        ),
                    )
                )

    # Cycle detection
    try:
        sorter = graphlib.TopologicalSorter(graph)
        list(sorter.static_order())
    except graphlib.CycleError as exc:
        cycle_info = str(exc)
        findings.append(
            Finding(
                layer=2,
                rule="L2-05/cross-composition-cycle",
                resource="",
                path="compositions",
                severity=Severity.CRITICAL,
                message=f"Cycle detected in cross-composition dependencies: {cycle_info}",
                remediation="Break the dependency cycle between compositions.",
            )
        )

    return findings
