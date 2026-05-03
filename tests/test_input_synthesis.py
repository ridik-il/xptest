"""Tests for pairwise input synthesis (Phase 5A)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import yaml

from xptest.exploration.input_synthesis import (
    _enumerate_domain,
    _greedy_pairwise_fallback,
    _minimal_value,
    _pairwise_cover,
    _structural_object_variants,
    extend_suite,
    generate_seed_suite,
)


def _write_xrd(spec_properties: dict, required: list[str] | None = None) -> str:
    """Write a minimal XRD YAML to a temp file and return its path."""
    schema = {"properties": spec_properties}
    if required is not None:
        schema["required"] = required

    xrd = {
        "apiVersion": "apiextensions.crossplane.io/v1",
        "kind": "CompositeResourceDefinition",
        "metadata": {"name": "xtest"},
        "spec": {
            "group": "test.example.com",
            "names": {"kind": "XTest", "plural": "xtests"},
            "versions": [
                {
                    "name": "v1alpha1",
                    "schema": {
                        "openAPIV3Schema": {
                            "type": "object",
                            "properties": {"spec": schema},
                        }
                    },
                }
            ],
        },
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
        yaml.safe_dump(xrd, fh, sort_keys=False)
        return fh.name


def test_enumerate_domain_boolean():
    assert _enumerate_domain("enabled", {"type": "boolean"}) == [True, False]


def test_enumerate_domain_enum():
    schema = {"type": "string", "enum": ["a", "b", "c"]}
    assert _enumerate_domain("tier", schema) == ["a", "b", "c"]


def test_enumerate_domain_integer_with_bounds():
    schema = {"type": "integer", "minimum": 1, "maximum": 10}
    domain = _enumerate_domain("replicas", schema)
    assert 1 in domain
    assert 10 in domain
    assert len(domain) >= 2


def test_enumerate_domain_region_string():
    domain = _enumerate_domain("region", {"type": "string"})
    assert "us-east-1" in domain


def test_enumerate_domain_namespace_string():
    domain = _enumerate_domain("namespace", {"type": "string"})
    assert "dev" in domain
    assert "prod" in domain


def test_pairwise_cover_two_params():
    params = [
        ("env", ["dev", "prod"]),
        ("region", ["us-east-1", "eu-west-1"]),
    ]
    combos = _pairwise_cover(params, max_count=100)
    # All 4 pairs must be covered
    pairs = set()
    for c in combos:
        pairs.add((c["env"], c["region"]))
    assert ("dev", "us-east-1") in pairs
    assert ("dev", "eu-west-1") in pairs
    assert ("prod", "us-east-1") in pairs
    assert ("prod", "eu-west-1") in pairs


def test_pairwise_cover_respects_max_count():
    params = [
        ("a", [1, 2, 3]),
        ("b", [4, 5, 6]),
        ("c", [7, 8, 9]),
    ]
    combos = _pairwise_cover(params, max_count=5)
    assert len(combos) <= 5


def test_greedy_fallback_covers_pairs():
    params = [
        ("x", ["a", "b"]),
        ("y", [1, 2]),
    ]
    combos = _greedy_pairwise_fallback(params, max_count=100)
    pairs = set()
    for c in combos:
        pairs.add((c["x"], c["y"]))
    assert len(pairs) == 4


def test_generate_seed_suite_from_xrd():
    path = _write_xrd(
        spec_properties={
            "region": {"type": "string"},
            "size": {"type": "integer", "minimum": 1, "maximum": 3},
        },
        required=["region", "size"],
    )
    try:
        candidates = generate_seed_suite(path, max_count=20)
        assert len(candidates) >= 2
        for label, doc in candidates:
            assert doc["kind"] == "XTest"
            assert "region" in doc["spec"]
            assert "size" in doc["spec"]
    finally:
        Path(path).unlink(missing_ok=True)


def test_generate_seed_suite_empty_xrd():
    path = _write_xrd(spec_properties={})
    try:
        candidates = generate_seed_suite(path, max_count=10)
        assert candidates == []
    finally:
        Path(path).unlink(missing_ok=True)


def test_extend_suite_produces_mutations():
    seed = [
        ("env=dev", {"apiVersion": "v1", "kind": "X", "spec": {"env": "dev"}}),
    ]
    params = [("env", ["dev", "prod", "staging"])]
    extensions = extend_suite(seed, ["branch-1"], params, max_iterations=3)
    assert len(extensions) >= 1
    # Should produce a mutation with different env value
    specs = [doc["spec"]["env"] for _, doc in extensions]
    assert any(v != "dev" for v in specs)


def test_structural_object_variants_with_sub_objects():
    """Object with optional object sub-properties produces toggle variants."""
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "corsConfiguration": {
                "type": "object",
                "properties": {
                    "corsRules": {
                        "type": "array",
                        "items": {"type": "object"},
                    }
                },
                "required": ["corsRules"],
            },
            "lifecycleConfiguration": {
                "type": "object",
                "properties": {
                    "rules": {
                        "type": "array",
                        "items": {"type": "object"},
                    }
                },
                "required": ["rules"],
            },
        },
    }
    variants = _structural_object_variants(schema)
    # Should have: base, +cors, +lifecycle, +both = 4
    assert len(variants) >= 4
    # Base variant has no cors or lifecycle
    assert "corsConfiguration" not in variants[0]
    assert "lifecycleConfiguration" not in variants[0]
    # At least one variant has corsConfiguration
    assert any("corsConfiguration" in v for v in variants)
    # At least one variant has lifecycleConfiguration
    assert any("lifecycleConfiguration" in v for v in variants)
    # All-on variant has both
    assert any(
        "corsConfiguration" in v and "lifecycleConfiguration" in v for v in variants
    )


def test_structural_object_variants_with_required():
    """Required fields appear in all variants."""
    schema = {
        "type": "object",
        "properties": {
            "deletionPolicy": {"type": "string", "enum": ["Orphan", "Delete"]},
            "optional_obj": {
                "type": "object",
                "properties": {"enabled": {"type": "boolean"}},
            },
        },
        "required": ["deletionPolicy"],
    }
    variants = _structural_object_variants(schema)
    for v in variants:
        assert "deletionPolicy" in v


def test_structural_object_variants_empty_props():
    """Object with no properties returns [{}]."""
    assert _structural_object_variants({"type": "object"}) == [{}]


def test_enumerate_domain_object_with_subprops():
    """_enumerate_domain for object type with sub-properties returns multiple variants."""
    schema = {
        "type": "object",
        "properties": {
            "versioningConfiguration": {
                "type": "object",
                "properties": {"status": {"type": "string", "enum": ["Enabled", "Suspended"]}},
            },
            "corsConfiguration": {
                "type": "object",
                "properties": {
                    "corsRules": {"type": "array", "items": {"type": "object"}},
                },
                "required": ["corsRules"],
            },
        },
    }
    domain = _enumerate_domain("bucketParameters", schema)
    assert len(domain) >= 3  # base + 2 toggles + all-on


def test_minimal_value_nested_object():
    """_minimal_value produces a valid minimal object with required fields."""
    schema = {
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["Enabled", "Suspended"]},
        },
        "required": ["status"],
    }
    val = _minimal_value("versioningConfiguration", schema)
    assert val == {"status": "Enabled"}


def test_minimal_value_array_of_objects():
    """_minimal_value for array of objects returns a list with one item."""
    schema = {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
        },
    }
    val = _minimal_value("rules", schema)
    assert isinstance(val, list)
    assert len(val) == 1


def test_generate_seed_suite_nested_objects():
    """Seed suite from XRD with nested object fields produces multiple variants."""
    path = _write_xrd(
        spec_properties={
            "region": {"type": "string"},
            "params": {
                "type": "object",
                "properties": {
                    "optA": {
                        "type": "object",
                        "properties": {"x": {"type": "string"}},
                    },
                    "optB": {
                        "type": "object",
                        "properties": {"y": {"type": "boolean"}},
                    },
                },
            },
        },
    )
    try:
        candidates = generate_seed_suite(path, max_count=50)
        # Should have multiple candidates with different params variants
        assert len(candidates) >= 3
        specs = [doc["spec"]["params"] for _, doc in candidates]
        has_a = any("optA" in s for s in specs)
        has_b = any("optB" in s for s in specs)
        assert has_a
        assert has_b
    finally:
        Path(path).unlink(missing_ok=True)
