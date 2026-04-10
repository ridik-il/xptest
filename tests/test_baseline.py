"""Tests for baseline/suppression functions in layer4/reporting.py."""

from __future__ import annotations

from xptest.layer4.reporting import (
    _finding_fingerprint,
    _normalize_resource,
    filter_baseline,
    save_baseline,
)
from xptest.models import Finding, Severity


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        layer=1,
        rule="L1-TEST",
        resource="my-resource",
        path="spec.forProvider.name",
        severity=Severity.WARNING,
        message="test message",
        remediation="fix it",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_normalize_resource_strips_bracket_prefix():
    assert _normalize_resource("[auto-xr-0:label] foo") == "foo"


def test_normalize_resource_no_prefix():
    assert _normalize_resource("foo") == "foo"


def test_finding_fingerprint_stable_across_case_ids():
    f1 = _make_finding(resource="[auto-xr-0:a] my-resource")
    f2 = _make_finding(resource="[auto-xr-5:b] my-resource")
    assert _finding_fingerprint(f1) == _finding_fingerprint(f2)


def test_finding_fingerprint_differs_for_different_rules():
    f1 = _make_finding(rule="L1-A")
    f2 = _make_finding(rule="L1-B")
    assert _finding_fingerprint(f1) != _finding_fingerprint(f2)


def test_save_and_filter_baseline_round_trip(tmp_path):
    findings = [_make_finding(), _make_finding(rule="L2-OTHER", message="other")]
    bp = str(tmp_path / "baseline.json")
    save_baseline(findings, bp, "test-comp")
    remaining, suppressed = filter_baseline(findings, bp)
    assert suppressed == 2
    assert remaining == []


def test_filter_baseline_missing_file(tmp_path):
    findings = [_make_finding()]
    remaining, suppressed = filter_baseline(findings, str(tmp_path / "nope.json"))
    assert suppressed == 0
    assert remaining == findings


def test_filter_baseline_new_finding_passes_through(tmp_path):
    a = _make_finding(rule="L1-A", message="a")
    b = _make_finding(rule="L1-B", message="b")
    bp = str(tmp_path / "baseline.json")
    save_baseline([a], bp)
    remaining, suppressed = filter_baseline([a, b], bp)
    assert suppressed == 1
    assert len(remaining) == 1
    assert remaining[0].rule == "L1-B"
