"""Tests for Go template branch coverage wrapper (Phase 5E)."""

from __future__ import annotations

from pathlib import Path

import pytest

from xptest.exploration.template_coverage import CoverageReport, measure_coverage

_GO_HELPER = (
    Path(__file__).resolve().parent.parent / "tools/template-coverage/bin/template-coverage"
)
_has_go_helper = _GO_HELPER.exists() and _GO_HELPER.is_file()


def test_empty_template_returns_100_pct():
    report = measure_coverage("", [{"key": "val"}])
    assert report.coverage_pct == 100.0
    assert report.total_branches == 0


def test_missing_helper_returns_trivial_report():
    report = measure_coverage(
        "{{ if .Values.enabled }}yes{{ end }}",
        [{"enabled": True}],
        go_helper_path="/nonexistent/binary",
    )
    # Without Go helper, returns trivial 100% (no instrumentation possible)
    assert report.coverage_pct == 100.0
    assert report.total_branches == 0


def test_coverage_report_dataclass():
    report = CoverageReport(
        total_branches=10,
        covered_branches=8,
        coverage_pct=80.0,
    )
    assert report.total_branches == 10
    assert len(report.uncovered) == 0


@pytest.mark.skipif(not _has_go_helper, reason="Go helper binary not built")
def test_go_helper_if_else_full_coverage():
    """Both true and false inputs → 100% coverage."""
    report = measure_coverage(
        "{{ if .enabled }}yes{{ else }}no{{ end }}",
        [{"enabled": True}, {"enabled": False}],
        go_helper_path=str(_GO_HELPER),
    )
    assert report.total_branches == 2
    assert report.covered_branches == 2
    assert report.coverage_pct == 100.0
    assert report.uncovered == []


@pytest.mark.skipif(not _has_go_helper, reason="Go helper binary not built")
def test_go_helper_if_else_partial_coverage():
    """Only true input → 50% coverage, false branch uncovered."""
    report = measure_coverage(
        "{{ if .enabled }}yes{{ else }}no{{ end }}",
        [{"enabled": True}],
        go_helper_path=str(_GO_HELPER),
    )
    assert report.total_branches == 2
    assert report.covered_branches == 1
    assert report.coverage_pct == 50.0
    assert len(report.uncovered) == 1
    assert report.uncovered[0].node_type == "if"


@pytest.mark.skipif(not _has_go_helper, reason="Go helper binary not built")
def test_go_helper_no_branches():
    """Template with no branch nodes → 100%."""
    report = measure_coverage(
        "hello {{ .name }}",
        [{"name": "world"}],
        go_helper_path=str(_GO_HELPER),
    )
    assert report.total_branches == 0
    assert report.coverage_pct == 100.0
