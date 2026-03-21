"""Tests for Layer 4 — Reporting."""

from __future__ import annotations

import io
import json
from pathlib import Path

from xptest.layer4 import reporting
from xptest.models import Finding, Severity


def _make_finding(severity: Severity, rule: str = "test/rule") -> Finding:
    return Finding(
        layer=1,
        rule=rule,
        resource="test-resource",
        path="spec.forProvider.field",
        severity=severity,
        message="Test message.",
        remediation="Fix it.",
    )


def test_exit_code_zero_when_no_criticals(tmp_path: Path):
    findings = [_make_finding(Severity.WARNING)]
    code = reporting.write(
        findings,
        output_path=str(tmp_path / "findings.json"),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code == 0


def test_exit_code_one_when_critical(tmp_path: Path):
    findings = [_make_finding(Severity.CRITICAL)]
    code = reporting.write(
        findings,
        output_path=str(tmp_path / "findings.json"),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code == 1


def test_json_output_matches_schema(tmp_path: Path):
    findings = [_make_finding(Severity.CRITICAL, rule="L1-01/schema-violation")]
    out_path = tmp_path / "findings.json"
    reporting.write(
        findings,
        output_path=str(out_path),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    data = json.loads(out_path.read_text())
    assert isinstance(data, list)
    assert len(data) == 1
    entry = data[0]
    for key in ("layer", "rule", "resource", "path", "severity", "message", "remediation"):
        assert key in entry, f"Missing key '{key}' in finding JSON"
    assert entry["severity"] == "CRITICAL"


def test_empty_findings_writes_empty_array(tmp_path: Path):
    out_path = tmp_path / "findings.json"
    code = reporting.write(
        [],
        output_path=str(out_path),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code == 0
    data = json.loads(out_path.read_text())
    assert data == []
