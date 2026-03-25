"""Tests for gap fixes round 3 — gaps 1–5 from third gap analysis."""

from __future__ import annotations

from xptest.models import CompositionObject, Severity

# ===========================================================================
# Gap 1: Explore report includes new metrics (integration-level check)
# ===========================================================================


class TestExploreReportMetrics:
    """Verify that the explore report section keys exist for new metrics."""

    def test_tway_coverage_report_keys(self):
        from xptest.exploration.input_synthesis import compute_tway_coverage

        params = [("a", [1, 2]), ("b", [True, False])]
        candidates = [("c1", {"spec": {"a": 1, "b": True}})]
        result = compute_tway_coverage(candidates, params)
        assert "t" in result
        assert "total_tuples" in result
        assert "covered_tuples" in result
        assert "coverage_pct" in result

    def test_mutation_score_report_keys(self):
        from xptest.exploration.fault_injection import compute_mutation_score

        result = compute_mutation_score(3, [])
        assert "faults_injected" in result
        assert "faults_detected" in result
        assert "mutation_score" in result

    def test_determinism_score_report_keys(self):
        from xptest.exploration.determinism import compute_determinism_score
        from xptest.logic.models import RenderedGraphSnapshot

        run_a = [RenderedGraphSnapshot(case_id="c1", input_flat={}, graph_hash="abc")]
        run_b = [RenderedGraphSnapshot(case_id="c1", input_flat={}, graph_hash="abc")]
        result = compute_determinism_score(run_a, run_b)
        assert "total_inputs" in result
        assert "identical_outputs" in result
        assert "determinism_score" in result


# ===========================================================================
# Gap 2: Remedy latency in DriftReport
# ===========================================================================


class TestRemedyLatency:
    def test_drift_report_has_remedy_latency_field(self):
        from xptest.drift import DriftReport

        report = DriftReport()
        assert hasattr(report, "remedy_latency_s")
        assert report.remedy_latency_s is None

    def test_drift_report_remedy_latency_value(self):
        from xptest.drift import DriftReport
        from xptest.drift.models import DriftFinding

        report = DriftReport(
            findings=[
                DriftFinding(
                    layer=5, rule="drift/test", resource="r", path="p",
                    severity=Severity.WARNING, message="m", remediation="r",
                ),
            ],
            total_duration_s=3.0,
            discovery_latency_s=0.5,
            remedy_latency_s=1.2,
            resources_checked=4,
        )
        assert report.remedy_latency_s == 1.2
        assert report.discovery_latency_s == 0.5


# ===========================================================================
# Gap 3: Failing input minimizer
# ===========================================================================


class TestMinimizer:
    def test_minimize_removes_unnecessary_keys(self):
        from xptest.exploration.minimizer import minimize_input

        # Violation reproduces as long as "bad_key" is present
        def check_fn(spec):
            return "bad_key" in spec

        failing = {"good_key": "a", "bad_key": "b", "neutral": "c"}
        minimized = minimize_input(failing, check_fn)
        assert "bad_key" in minimized
        assert "good_key" not in minimized
        assert "neutral" not in minimized

    def test_minimize_keeps_all_if_all_needed(self):
        from xptest.exploration.minimizer import minimize_input

        # Violation requires all keys
        def check_fn(spec):
            return "a" in spec and "b" in spec

        failing = {"a": 1, "b": 2}
        minimized = minimize_input(failing, check_fn)
        assert minimized == {"a": 1, "b": 2}

    def test_minimize_empty_input(self):
        from xptest.exploration.minimizer import minimize_input

        minimized = minimize_input({}, lambda spec: True)
        assert minimized == {}

    def test_save_regression_artifact(self, tmp_path):
        from xptest.exploration.minimizer import save_regression_artifact

        path = save_regression_artifact(
            {"key": "val"},
            "inv/type-coverage",
            "explore-0:test",
            output_dir=str(tmp_path / "regressions"),
        )
        import json
        from pathlib import Path

        artifact = json.loads(Path(path).read_text())
        assert artifact["rule"] == "inv/type-coverage"
        assert artifact["minimized_spec"] == {"key": "val"}

    def test_minimize_respects_max_iterations(self):
        from xptest.exploration.minimizer import minimize_input

        call_count = 0

        def check_fn(spec):
            nonlocal call_count
            call_count += 1
            return True

        failing = {f"k{i}": i for i in range(20)}
        minimize_input(failing, check_fn, max_iterations=5)
        assert call_count <= 5


# ===========================================================================
# Gap 4: evaluate.py additional metrics
# ===========================================================================


class TestEvaluateAdditionalMetrics:
    def test_compute_additional_metrics_returns_expected_keys(self, tmp_path):
        """Verify _compute_additional_metrics returns tway, mutation, determinism."""
        from xptest.config import Config
        from xptest.evaluate import _compute_additional_metrics

        # Create minimal fixtures dir with a valid fixture
        valid_dir = tmp_path / "valid"
        valid_dir.mkdir()

        config = Config()
        # Use a nonexistent XRD — should gracefully return defaults
        result = _compute_additional_metrics(
            tmp_path, "/nonexistent/xrd.yaml", config, {}
        )
        assert "tway_coverage" in result
        assert "mutation_score" in result
        assert "determinism_score" in result

    def test_mutation_score_from_empty_fixtures(self):
        """With no fi/ findings, mutation score should be 1.0."""
        from xptest.exploration.fault_injection import compute_mutation_score

        result = compute_mutation_score(0, [])
        assert result["mutation_score"] == 1.0


# ===========================================================================
# Gap 5: L1-05 docstring fixed
# ===========================================================================


class TestDocstringFixed:
    def test_l1_05_docstring_no_longer_says_stub(self):
        import xptest.layer1.static as static_mod

        docstring = static_mod.__doc__ or ""
        assert "stub" not in docstring.lower()

    def test_l1_06_listed_in_docstring(self):
        import xptest.layer1.static as static_mod

        docstring = static_mod.__doc__ or ""
        assert "L1-06" in docstring


# ===========================================================================
# Helper
# ===========================================================================


def _make_composition_object(resources=None):
    from xptest.models import CompositionMode

    return CompositionObject(
        composition_name="test",
        composition_path="/tmp/test.yaml",
        xrd_name="test-xrd",
        xrd_path="/tmp/xrd.yaml",
        mode=CompositionMode.RESOURCES,
        resources=resources or [],
    )
