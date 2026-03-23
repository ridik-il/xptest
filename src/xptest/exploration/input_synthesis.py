"""Pairwise input synthesis from XRD schema (§7.2, §4.4.2).

Two-phase generation:
  Phase 1 — seed suite via pairwise covering array (t=2, t=3 for policy-critical).
  Phase 2 — coverage-guided mutation (extends seed suite until branch stability).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def generate_seed_suite(
    xrd_path: str,
    max_count: int = 100,
    xr_kind_override: str = "",
) -> list[tuple[str, dict[str, Any]]]:
    """Build pairwise covering array of XR candidates from an XRD schema.

    Returns list of (label, xr_doc) tuples ready for crossplane render.
    """
    xrd = _read_xrd(xrd_path)
    spec = xrd.get("spec", {})
    group = spec.get("group", "")
    versions = spec.get("versions", [])
    if not versions:
        return []

    version = versions[0].get("name", "v1alpha1")
    kind = xr_kind_override or spec.get("names", {}).get("kind", "Composite")
    api_version = f"{group}/{version}" if group else version

    schema = (
        versions[0]
        .get("schema", {})
        .get("openAPIV3Schema", {})
        .get("properties", {})
        .get("spec", {})
    )
    params = _extract_parameters(schema)
    if not params:
        return []

    combos = _pairwise_cover(params, max_count=max_count)

    candidates: list[tuple[str, dict[str, Any]]] = []
    for idx, combo in enumerate(combos):
        name = f"explore-xr-{idx}"
        xr_doc = {
            "apiVersion": api_version,
            "kind": kind,
            "metadata": {
                "name": name,
                "labels": {"crossplane.io/claim-name": name},
            },
            "spec": combo,
        }
        label = ",".join(f"{k}={v}" for k, v in sorted(combo.items()))
        candidates.append((label, xr_doc))

    return candidates


def extend_suite(
    seed_candidates: list[tuple[str, dict[str, Any]]],
    uncovered_branches: list[str],
    params: list[tuple[str, list[Any]]],
    max_iterations: int = 50,
) -> list[tuple[str, dict[str, Any]]]:
    """Coverage-guided mutation: extend seed suite to cover uncovered branches.

    For each uncovered branch, select nearest seed input, mutate one parameter,
    yield new candidate. Iterate until branches stabilize or limit reached.
    """
    if not uncovered_branches or not params:
        return []

    extensions: list[tuple[str, dict[str, Any]]] = []
    base_idx = len(seed_candidates)

    for iteration in range(min(max_iterations, len(uncovered_branches))):
        # Pick seed to mutate (round-robin across seeds)
        seed_label, seed_doc = seed_candidates[iteration % len(seed_candidates)]
        seed_spec = dict(seed_doc.get("spec", {}))

        # Mutate one parameter to next value in domain
        param_name, param_domain = params[iteration % len(params)]
        current = seed_spec.get(param_name)
        next_val = _next_domain_value(current, param_domain)
        if next_val is None:
            continue

        mutated_spec = {**seed_spec, param_name: next_val}
        name = f"explore-xr-mut-{base_idx + len(extensions)}"
        api_version = seed_doc.get("apiVersion", "")
        kind = seed_doc.get("kind", "")
        xr_doc = {
            "apiVersion": api_version,
            "kind": kind,
            "metadata": {
                "name": name,
                "labels": {"crossplane.io/claim-name": name},
            },
            "spec": mutated_spec,
        }
        label = ",".join(f"{k}={v}" for k, v in sorted(mutated_spec.items()))
        extensions.append((label, xr_doc))

    return extensions


def _extract_parameters(
    spec_schema: dict[str, Any],
) -> list[tuple[str, list[Any]]]:
    """Extract parameter names and their domain values from XRD spec schema."""
    props: dict[str, Any] = spec_schema.get("properties", {})
    required: list[str] = spec_schema.get("required", [])

    # Prioritize required fields, then include optional ones
    field_names = list(required)
    for name in props:
        if name not in field_names:
            field_names.append(name)

    params: list[tuple[str, list[Any]]] = []
    for name in field_names:
        if name not in props:
            continue
        field_schema = props[name]
        domain = _enumerate_domain(name, field_schema)
        if domain:
            params.append((name, domain))

    return params


def _enumerate_domain(field_name: str, schema: dict[str, Any]) -> list[Any]:
    """Domain enumeration per parameter type (§7.2)."""
    # Enum: all values
    enum_vals = schema.get("enum")
    if isinstance(enum_vals, list) and enum_vals:
        return enum_vals

    field_type = schema.get("type", "string")
    lower = field_name.lower()

    if field_type == "boolean":
        return [True, False]

    if field_type in {"integer", "number"}:
        minimum = schema.get("minimum", 1)
        maximum = schema.get("maximum", 100)
        values = [minimum, maximum]
        # Add boundary value
        mid = (minimum + maximum) // 2
        if mid not in values:
            values.append(mid)
        return sorted(set(values))

    if field_type == "string":
        # Domain-aware string samples
        if "region" in lower:
            return ["us-east-1", "eu-west-1"]
        if "namespace" in lower or lower in {"env", "environment"}:
            return ["dev", "prod", "staging"]
        if "cidr" in lower:
            return ["10.0.0.0/16", "172.16.0.0/16"]
        if "name" in lower:
            return ["demo", "test-resource"]
        if "arn" in lower:
            return ["arn:aws:iam::123456789012:role/sample"]
        # Generic string
        return ["sample-a", "sample-b"]

    if field_type == "array":
        items = schema.get("items", {})
        if items.get("type") == "string":
            return [[], ["value-1"]]
        return [[], [{}]]

    if field_type == "object":
        return [{}]

    return ["sample"]


def _pairwise_cover(
    params: list[tuple[str, list[Any]]],
    max_count: int = 100,
) -> list[dict[str, Any]]:
    """Generate pairwise covering array (t=2).

    Uses allpairspy if available, falls back to greedy algorithm.
    """
    if not params:
        return []

    try:
        from allpairspy import AllPairs

        names = [name for name, _ in params]
        domains = [domain for _, domain in params]

        combos: list[dict[str, Any]] = []
        for row in AllPairs(domains):
            if len(combos) >= max_count:
                break
            combos.append(dict(zip(names, row)))
        return combos

    except ImportError:
        return _greedy_pairwise_fallback(params, max_count)


def _greedy_pairwise_fallback(
    params: list[tuple[str, list[Any]]],
    max_count: int,
) -> list[dict[str, Any]]:
    """Simple greedy pairwise fallback when allpairspy is not installed.

    Generates rows that cover as many uncovered pairs as possible.
    """
    names = [name for name, _ in params]
    domains = [domain for _, domain in params]
    n = len(params)

    if n == 0:
        return []
    if n == 1:
        return [{names[0]: v} for v in domains[0][:max_count]]

    # Collect all pairs that need covering
    uncovered: set[tuple[int, Any, int, Any]] = set()
    for i in range(n):
        for j in range(i + 1, n):
            for vi in domains[i]:
                for vj in domains[j]:
                    uncovered.add((i, _hashable(vi), j, _hashable(vj)))

    combos: list[dict[str, Any]] = []
    while uncovered and len(combos) < max_count:
        best_row: dict[str, Any] = {}
        best_covered = 0

        # Try each combination of first two uncovered-pair values
        for pair in list(uncovered)[:50]:  # limit search for performance
            i, vi_h, j, vj_h = pair
            vi = _unhash(vi_h, domains[i])
            vj = _unhash(vj_h, domains[j])
            row = {names[k]: domains[k][0] for k in range(n)}
            row[names[i]] = vi
            row[names[j]] = vj

            covered = _count_covered(row, names, uncovered)
            if covered > best_covered:
                best_covered = covered
                best_row = row

        if not best_row:
            break

        combos.append(best_row)
        # Remove covered pairs
        for i in range(n):
            for j in range(i + 1, n):
                vi_h = _hashable(best_row[names[i]])
                vj_h = _hashable(best_row[names[j]])
                uncovered.discard((i, vi_h, j, vj_h))

    return combos


def _count_covered(
    row: dict[str, Any],
    names: list[str],
    uncovered: set[tuple[int, Any, int, Any]],
) -> int:
    n = len(names)
    count = 0
    for i in range(n):
        for j in range(i + 1, n):
            vi_h = _hashable(row[names[i]])
            vj_h = _hashable(row[names[j]])
            if (i, vi_h, j, vj_h) in uncovered:
                count += 1
    return count


def _hashable(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    if isinstance(value, dict):
        return tuple(sorted(value.items()))
    return value


def _unhash(h: Any, domain: list[Any]) -> Any:
    """Find the original domain value matching a hashable representation."""
    for v in domain:
        if _hashable(v) == h:
            return v
    return domain[0] if domain else None


def _next_domain_value(current: Any, domain: list[Any]) -> Any | None:
    """Pick the next domain value different from current."""
    for v in domain:
        if v != current:
            return v
    return None


def _read_xrd(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    with p.open() as fh:
        doc = yaml.safe_load(fh) or {}
    return doc if isinstance(doc, dict) else {}
