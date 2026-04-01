"""Tests for pairwise input synthesis (Phase 5A)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import yaml

from xptest.exploration.input_synthesis import (
    _enumerate_domain,
    _greedy_pairwise_fallback,
    _pairwise_cover,
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
