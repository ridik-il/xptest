"""Evaluation tests — parametrized across the full fixture set.

Each fixture YAML has a companion *-expected.json listing the expected findings.
These tests run Layers 1+2 (no OPA needed) and verify that:
  1. Every expected finding is produced (recall).
  2. No unexpected findings are produced (precision).

Layer 3 (OPA) integration tests are in test_layer3.py and require OPA on PATH.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from xptest.layer1 import static as layer1
from xptest.layer2 import dependency as layer2
from xptest.loader import load

_HERE = Path(__file__).parent
FIXTURES_DIR = _HERE.parent / "fixtures"
XRD_PATH = str(FIXTURES_DIR / "xrd.yaml")


def _collect_fixtures(*subdirs: str):
    """Yield (fixture_yaml, expected_json) pairs from fixture subdirectories."""
    for subdir in subdirs:
        d = FIXTURES_DIR / subdir
        if not d.is_dir():
            continue
        for yaml_file in sorted(d.glob("*.yaml")):
            expected_file = yaml_file.with_name(
                yaml_file.stem + "-expected.json"
            )
            if expected_file.exists():
                yield pytest.param(
                    yaml_file,
                    expected_file,
                    id=f"{subdir}/{yaml_file.stem}",
                )


def _run_layers_1_2(fixture_path: Path):
    obj = load(str(fixture_path), XRD_PATH)
    findings = layer1.run(obj) + layer2.run(obj)
    return findings


# ────────────────────────────────────────────────────────
# Valid compositions: expect zero findings from L1+L2
# ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "fixture_yaml,expected_json",
    list(_collect_fixtures("valid")),
)
def test_valid_fixtures_no_findings(fixture_yaml, expected_json):
    findings = _run_layers_1_2(fixture_yaml)
    expected = json.loads(expected_json.read_text())
    assert expected == [], f"Expected.json should be empty for valid fixtures: {expected}"
    # Filter to L1+L2 only
    l12 = [f for f in findings if f.layer in (1, 2)]
    assert l12 == [], f"Valid fixture {fixture_yaml.name} produced findings: {l12}"


# ────────────────────────────────────────────────────────
# Dependency error compositions: check expected L2 findings
# ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "fixture_yaml,expected_json",
    list(_collect_fixtures("dep-errors")),
)
def test_dep_error_fixtures(fixture_yaml, expected_json):
    findings = _run_layers_1_2(fixture_yaml)
    expected = json.loads(expected_json.read_text())

    found_rules = {f.rule for f in findings}

    # Recall: every expected rule must be present
    for exp in expected:
        assert exp["rule"] in found_rules, (
            f"Expected rule '{exp['rule']}' not found. "
            f"Got: {found_rules}"
        )

    # Check severity matches
    for exp in expected:
        matching = [f for f in findings if f.rule == exp["rule"]]
        assert len(matching) >= 1
        assert matching[0].severity.value == exp["severity"], (
            f"Rule '{exp['rule']}' severity mismatch: "
            f"expected {exp['severity']}, got {matching[0].severity.value}"
        )


# ────────────────────────────────────────────────────────
# Policy violation compositions: check expected L3 rule labels
# (These only verify expected.json structure; actual OPA tests are in test_layer3.py)
# ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "fixture_yaml,expected_json",
    list(_collect_fixtures("policy-violations")),
)
def test_policy_violation_expected_labels_valid(fixture_yaml, expected_json):
    """Verify that expected.json files are well-formed and reference Layer 3."""
    expected = json.loads(expected_json.read_text())
    assert len(expected) > 0, f"Policy fixture {fixture_yaml.name} has empty expected.json"
    for exp in expected:
        assert exp["layer"] == 3, f"Policy expected should be layer 3, got {exp}"
        assert "rule" in exp
        assert "severity" in exp
        assert exp["severity"] in ("CRITICAL", "WARNING", "INFO")
