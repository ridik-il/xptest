"""Tests for Layer 2 — Dependency Validation."""

from __future__ import annotations

from pathlib import Path

from xptest.layer2 import dependency as layer2
from xptest.loader import load
from xptest.models import Severity

_HERE = Path(__file__).parent
FIXTURES_DIR = _HERE.parent / "fixtures"
XRD_PATH = str(FIXTURES_DIR / "xrd.yaml")


def _run(fixture_path, crd_bundle: str = ""):
    obj = load(str(fixture_path), XRD_PATH, crd_bundle_path=crd_bundle)
    return layer2.run(obj)


def test_valid_composition_no_dep_findings():
    findings = _run(FIXTURES_DIR / "valid" / "vpc-subnet-iam.yaml")
    dep_findings = [f for f in findings if f.layer == 2]
    assert dep_findings == [], f"Expected no Layer 2 findings, got: {dep_findings}"


def test_cycle_detected():
    findings = _run(FIXTURES_DIR / "dep-errors" / "vpc-cycle.yaml")
    cycles = [f for f in findings if f.rule == "L2-02/dependency-cycle"]
    assert len(cycles) >= 1
    assert cycles[0].severity == Severity.CRITICAL


def test_dangling_reference_detected():
    findings = _run(FIXTURES_DIR / "dep-errors" / "vpc-dangling.yaml")
    dangling = [f for f in findings if f.rule == "L2-03/dangling-reference"]
    assert len(dangling) >= 1
    assert dangling[0].severity == Severity.CRITICAL


def test_missing_readiness_gate_detected():
    findings = _run(FIXTURES_DIR / "dep-errors" / "vpc-missing-readiness.yaml")
    missing = [f for f in findings if f.rule == "L2-04/missing-readiness-gate"]
    assert len(missing) >= 1
    assert missing[0].severity == Severity.WARNING
    assert missing[0].resource == "main-vpc"
