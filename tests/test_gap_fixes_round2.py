"""Tests for gap fixes round 2 — gaps 1–9 from second gap analysis."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import yaml

from xptest.models import ComposedResource, CompositionObject, Finding, Severity

# ===========================================================================
# Gap 1: t-way input coverage metric
# ===========================================================================


class TestTwayCoverage:
    def test_full_coverage_two_params(self):
        from xptest.exploration.input_synthesis import compute_tway_coverage

        params = [("a", [1, 2]), ("b", [True, False])]
        candidates = [
            ("c1", {"spec": {"a": 1, "b": True}}),
            ("c2", {"spec": {"a": 1, "b": False}}),
            ("c3", {"spec": {"a": 2, "b": True}}),
            ("c4", {"spec": {"a": 2, "b": False}}),
        ]
        result = compute_tway_coverage(candidates, params, t=2)
        assert result["coverage_pct"] == 100.0
        assert result["total_tuples"] == 4
        assert result["covered_tuples"] == 4

    def test_partial_coverage(self):
        from xptest.exploration.input_synthesis import compute_tway_coverage

        params = [("a", [1, 2]), ("b", [True, False])]
        candidates = [
            ("c1", {"spec": {"a": 1, "b": True}}),
        ]
        result = compute_tway_coverage(candidates, params, t=2)
        assert result["coverage_pct"] == 25.0
        assert result["covered_tuples"] == 1

    def test_empty_candidates(self):
        from xptest.exploration.input_synthesis import compute_tway_coverage

        result = compute_tway_coverage([], [("a", [1])], t=2)
        assert result["coverage_pct"] == 100.0
        assert result["total_tuples"] == 0

    def test_empty_params(self):
        from xptest.exploration.input_synthesis import compute_tway_coverage

        result = compute_tway_coverage([("c1", {"spec": {}})], [], t=2)
        assert result["coverage_pct"] == 100.0

    def test_three_params_t2(self):
        from xptest.exploration.input_synthesis import compute_tway_coverage

        params = [("a", [1, 2]), ("b", [True, False]), ("c", ["x", "y"])]
        # These 4 candidates should cover most 2-way pairs
        candidates = [
            ("c1", {"spec": {"a": 1, "b": True, "c": "x"}}),
            ("c2", {"spec": {"a": 2, "b": False, "c": "y"}}),
            ("c3", {"spec": {"a": 1, "b": False, "c": "y"}}),
            ("c4", {"spec": {"a": 2, "b": True, "c": "x"}}),
        ]
        result = compute_tway_coverage(candidates, params, t=2)
        assert result["total_tuples"] == 12
        assert result["covered_tuples"] >= 8  # high coverage
        assert result["coverage_pct"] > 60.0


# ===========================================================================
# Gap 2: Mutation score metric
# ===========================================================================


class TestMutationScore:
    def test_all_detected(self):
        from xptest.exploration.fault_injection import compute_mutation_score

        findings = [
            Finding(
                layer=7, rule="fi/resource-disappeared-under-fault",
                resource="r1", path="", severity=Severity.WARNING,
                message="", remediation="",
            ),
            Finding(
                layer=7, rule="fi/render-failed-under-fault",
                resource="r2", path="", severity=Severity.CRITICAL,
                message="", remediation="",
            ),
        ]
        result = compute_mutation_score(2, findings)
        assert result["mutation_score"] == 1.0
        assert result["faults_detected"] == 2

    def test_partial_detection(self):
        from xptest.exploration.fault_injection import compute_mutation_score

        findings = [
            Finding(
                layer=7, rule="fi/resource-disappeared-under-fault",
                resource="r1", path="", severity=Severity.WARNING,
                message="", remediation="",
            ),
        ]
        result = compute_mutation_score(4, findings)
        assert result["mutation_score"] == 0.25

    def test_zero_faults(self):
        from xptest.exploration.fault_injection import compute_mutation_score

        result = compute_mutation_score(0, [])
        assert result["mutation_score"] == 1.0

    def test_non_fi_findings_not_counted(self):
        from xptest.exploration.fault_injection import compute_mutation_score

        findings = [
            Finding(
                layer=1, rule="L1-03/duplicate-resource-name",
                resource="r1", path="", severity=Severity.CRITICAL,
                message="", remediation="",
            ),
        ]
        result = compute_mutation_score(2, findings)
        assert result["faults_detected"] == 0
        assert result["mutation_score"] == 0.0


# ===========================================================================
# Gap 3: Determinism score
# ===========================================================================


class TestDeterminismScore:
    def test_identical_runs(self):
        from xptest.exploration.determinism import compute_determinism_score
        from xptest.logic.models import RenderedGraphSnapshot

        run_a = [
            RenderedGraphSnapshot(case_id="c1", input_flat={}, graph_hash="abc"),
            RenderedGraphSnapshot(case_id="c2", input_flat={}, graph_hash="def"),
        ]
        run_b = [
            RenderedGraphSnapshot(case_id="c1", input_flat={}, graph_hash="abc"),
            RenderedGraphSnapshot(case_id="c2", input_flat={}, graph_hash="def"),
        ]
        result = compute_determinism_score(run_a, run_b)
        assert result["determinism_score"] == 1.0
        assert result["identical_outputs"] == 2

    def test_different_runs(self):
        from xptest.exploration.determinism import compute_determinism_score
        from xptest.logic.models import RenderedGraphSnapshot

        run_a = [
            RenderedGraphSnapshot(case_id="c1", input_flat={}, graph_hash="abc"),
            RenderedGraphSnapshot(case_id="c2", input_flat={}, graph_hash="def"),
        ]
        run_b = [
            RenderedGraphSnapshot(case_id="c1", input_flat={}, graph_hash="abc"),
            RenderedGraphSnapshot(case_id="c2", input_flat={}, graph_hash="xyz"),
        ]
        result = compute_determinism_score(run_a, run_b)
        assert result["determinism_score"] == 0.5
        assert result["identical_outputs"] == 1

    def test_empty_runs(self):
        from xptest.exploration.determinism import compute_determinism_score

        result = compute_determinism_score([], [])
        assert result["determinism_score"] == 1.0
        assert result["total_inputs"] == 0


# ===========================================================================
# Gap 4: Severity overrides applied to L1/L2 findings
# ===========================================================================


class TestSeverityOverrides:
    def test_override_warning_to_critical(self):
        from xptest.validation.facade import apply_severity_overrides

        findings = [
            Finding(
                layer=1, rule="L1-06/environment-config-missing",
                resource="", path="", severity=Severity.WARNING,
                message="", remediation="",
            ),
        ]
        apply_severity_overrides(findings, {"L1-06/environment-config-missing": "CRITICAL"})
        assert findings[0].severity == Severity.CRITICAL

    def test_override_critical_to_warning(self):
        from xptest.validation.facade import apply_severity_overrides

        findings = [
            Finding(
                layer=2, rule="L2-02/cycle-detected",
                resource="", path="", severity=Severity.CRITICAL,
                message="", remediation="",
            ),
        ]
        apply_severity_overrides(findings, {"L2-02/cycle-detected": "WARNING"})
        assert findings[0].severity == Severity.WARNING

    def test_no_overrides_no_change(self):
        from xptest.validation.facade import apply_severity_overrides

        findings = [
            Finding(
                layer=1, rule="L1-03/duplicate-resource-name",
                resource="", path="", severity=Severity.CRITICAL,
                message="", remediation="",
            ),
        ]
        apply_severity_overrides(findings, {})
        assert findings[0].severity == Severity.CRITICAL

    def test_unmatched_rule_no_change(self):
        from xptest.validation.facade import apply_severity_overrides

        findings = [
            Finding(
                layer=1, rule="L1-03/duplicate-resource-name",
                resource="", path="", severity=Severity.CRITICAL,
                message="", remediation="",
            ),
        ]
        apply_severity_overrides(findings, {"some-other-rule": "WARNING"})
        assert findings[0].severity == Severity.CRITICAL


# ===========================================================================
# Gap 6: Multi-composition dependency graph (L2-05)
# ===========================================================================


class TestCrossCompositionOrdering:
    def test_valid_manifest(self):
        from xptest.layer2.dependency import check_cross_composition_ordering

        manifest = {
            "compositions": [
                {"name": "network", "provides": ["vpc-id", "subnet-ids"]},
                {"name": "database", "depends_on": ["network"], "consumes": ["vpc-id"]},
            ]
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as fh:
            yaml.safe_dump(manifest, fh)
            path = fh.name

        try:
            findings = check_cross_composition_ordering(path)
            assert len(findings) == 0
        finally:
            Path(path).unlink()

    def test_unknown_dependency(self):
        from xptest.layer2.dependency import check_cross_composition_ordering

        manifest = {
            "compositions": [
                {"name": "database", "depends_on": ["nonexistent"]},
            ]
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as fh:
            yaml.safe_dump(manifest, fh)
            path = fh.name

        try:
            findings = check_cross_composition_ordering(path)
            assert any(f.rule == "L2-05/unknown-composition-dependency" for f in findings)
        finally:
            Path(path).unlink()

    def test_unresolved_output(self):
        from xptest.layer2.dependency import check_cross_composition_ordering

        manifest = {
            "compositions": [
                {"name": "network", "provides": ["vpc-id"]},
                {"name": "database", "depends_on": ["network"], "consumes": ["missing-output"]},
            ]
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as fh:
            yaml.safe_dump(manifest, fh)
            path = fh.name

        try:
            findings = check_cross_composition_ordering(path)
            assert any(
                f.rule == "L2-05/unresolved-cross-composition-output" for f in findings
            )
        finally:
            Path(path).unlink()

    def test_cycle_detection(self):
        from xptest.layer2.dependency import check_cross_composition_ordering

        manifest = {
            "compositions": [
                {"name": "a", "depends_on": ["b"]},
                {"name": "b", "depends_on": ["a"]},
            ]
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as fh:
            yaml.safe_dump(manifest, fh)
            path = fh.name

        try:
            findings = check_cross_composition_ordering(path)
            assert any(f.rule == "L2-05/cross-composition-cycle" for f in findings)
        finally:
            Path(path).unlink()

    def test_missing_file(self):
        from xptest.layer2.dependency import check_cross_composition_ordering

        findings = check_cross_composition_ordering("/nonexistent/manifest.yaml")
        assert len(findings) == 0


# ===========================================================================
# Gap 7: L1-05 deprecated field detection
# ===========================================================================


class TestDeprecatedFields:
    def test_deprecated_sg_ingress(self):
        from xptest.layer1.static import _check_deprecated_fields

        obj = _make_composition_object(resources=[
            ComposedResource(
                name="my-sg",
                api_version="ec2.aws.upbound.io/v1beta1",
                kind="SecurityGroup",
                spec={"forProvider": {"ingress": [{"fromPort": 22}]}},
            ),
        ])
        findings = _check_deprecated_fields(obj)
        assert len(findings) == 1
        assert findings[0].rule == "L1-05/deprecated-field"
        assert "ingress" in findings[0].message

    def test_deprecated_s3_acl(self):
        from xptest.layer1.static import _check_deprecated_fields

        obj = _make_composition_object(resources=[
            ComposedResource(
                name="my-bucket",
                api_version="s3.aws.upbound.io/v1beta1",
                kind="Bucket",
                spec={"forProvider": {"acl": "private"}},
            ),
        ])
        findings = _check_deprecated_fields(obj)
        assert len(findings) == 1
        assert "acl" in findings[0].message

    def test_no_deprecated_fields(self):
        from xptest.layer1.static import _check_deprecated_fields

        obj = _make_composition_object(resources=[
            ComposedResource(
                name="my-vpc",
                api_version="ec2.aws.upbound.io/v1beta1",
                kind="VPC",
                spec={"forProvider": {"cidrBlock": "10.0.0.0/16"}},
            ),
        ])
        findings = _check_deprecated_fields(obj)
        assert len(findings) == 0

    def test_different_provider_no_match(self):
        from xptest.layer1.static import _check_deprecated_fields

        obj = _make_composition_object(resources=[
            ComposedResource(
                name="my-sg",
                api_version="gcp.upbound.io/v1beta1",
                kind="SecurityGroup",
                spec={"forProvider": {"ingress": [{"fromPort": 22}]}},
            ),
        ])
        findings = _check_deprecated_fields(obj)
        assert len(findings) == 0


# ===========================================================================
# Gap 8: bc/identity-change breaking change rule
# ===========================================================================


class TestIdentityChange:
    def test_no_identity_change(self):
        from xptest.exploration.breaking_change import detect_breaking_changes
        from xptest.logic.models import RenderedGraphSnapshot, RenderedResourceNode

        baseline = {
            "resources": [
                {
                    "composition-resource-name": "vpc",
                    "deletionPolicy": "Delete",
                    "managementPolicies": ["*"],
                    "position": 0,
                    "apiVersion": "ec2.aws.upbound.io/v1beta1",
                    "kind": "VPC",
                },
            ]
        }
        snapshot = RenderedGraphSnapshot(
            case_id="test-0",
            input_flat={},
            resources=[
                RenderedResourceNode(
                    resource_id="vpc-id",
                    role="managed",
                    api_version="ec2.aws.upbound.io/v1beta1",
                    kind="VPC",
                    name="vpc",
                    spec={"deletionPolicy": "Delete", "managementPolicies": ["*"]},
                    identity_source="annotation",
                ),
            ],
        )
        findings = detect_breaking_changes(baseline, [snapshot])
        assert not any(f.rule == "bc/identity-change" for f in findings)

    def test_identity_change_detected(self):
        from xptest.exploration.breaking_change import detect_breaking_changes
        from xptest.logic.models import RenderedGraphSnapshot, RenderedResourceNode

        baseline = {
            "resources": [
                {
                    "composition-resource-name": "vpc",
                    "deletionPolicy": "Delete",
                    "managementPolicies": ["*"],
                    "position": 0,
                    "apiVersion": "ec2.aws.upbound.io/v1beta1",
                    "kind": "VPC",
                },
            ]
        }
        # Same position but different name and kind
        snapshot = RenderedGraphSnapshot(
            case_id="test-0",
            input_flat={},
            resources=[
                RenderedResourceNode(
                    resource_id="subnet-id",
                    role="managed",
                    api_version="ec2.aws.upbound.io/v1beta1",
                    kind="Subnet",
                    name="subnet",
                    spec={"deletionPolicy": "Delete", "managementPolicies": ["*"]},
                    identity_source="annotation",
                ),
            ],
        )
        findings = detect_breaking_changes(baseline, [snapshot])
        identity_findings = [f for f in findings if f.rule == "bc/identity-change"]
        assert len(identity_findings) == 1
        assert "position 0" in identity_findings[0].message

    def test_identity_change_gvk_only(self):
        from xptest.exploration.breaking_change import detect_breaking_changes
        from xptest.logic.models import RenderedGraphSnapshot, RenderedResourceNode

        baseline = {
            "resources": [
                {
                    "composition-resource-name": "vpc",
                    "deletionPolicy": "Delete",
                    "managementPolicies": ["*"],
                    "position": 0,
                    "apiVersion": "ec2.aws.upbound.io/v1beta1",
                    "kind": "VPC",
                },
            ]
        }
        # Same name but different kind at same position
        snapshot = RenderedGraphSnapshot(
            case_id="test-0",
            input_flat={},
            resources=[
                RenderedResourceNode(
                    resource_id="vpc-id",
                    role="managed",
                    api_version="ec2.aws.upbound.io/v1beta1",
                    kind="Subnet",
                    name="vpc",
                    spec={"deletionPolicy": "Delete", "managementPolicies": ["*"]},
                    identity_source="annotation",
                ),
            ],
        )
        findings = detect_breaking_changes(baseline, [snapshot])
        identity_findings = [f for f in findings if f.rule == "bc/identity-change"]
        assert len(identity_findings) == 1


# ===========================================================================
# Gap 9: Discovery/remedy latency timing
# ===========================================================================


class TestDriftTiming:
    def test_drift_report_has_timing(self):
        from xptest.drift import DriftReport

        report = DriftReport(
            findings=[],
            total_duration_s=1.5,
            discovery_latency_s=None,
            resources_checked=3,
        )
        assert report.total_duration_s == 1.5
        assert report.discovery_latency_s is None
        assert report.resources_checked == 3

    def test_drift_report_with_discovery(self):
        from xptest.drift import DriftReport
        from xptest.drift.models import DriftFinding

        finding = DriftFinding(
            layer=5, rule="drift/vpc-mismatch", resource="vpc",
            path="cidrBlock", severity=Severity.CRITICAL,
            message="", remediation="",
        )
        report = DriftReport(
            findings=[finding],
            total_duration_s=2.0,
            discovery_latency_s=0.3,
            resources_checked=5,
        )
        assert report.discovery_latency_s == 0.3
        assert len(report.findings) == 1

    def test_run_with_timing_returns_report(self):
        """Verify run_with_timing returns DriftReport (mocked AWS)."""
        try:
            import boto3  # noqa: F401
        except ImportError:
            return  # skip if boto3 not installed

        from xptest.config import Config
        from xptest.drift import run_with_timing

        obj = _make_composition_object(resources=[])
        config = Config()

        mock_session = MagicMock()
        report = run_with_timing(obj, config, session=mock_session)
        assert report.total_duration_s >= 0
        assert report.resources_checked == 0
        assert report.findings == []


# ===========================================================================
# Helpers
# ===========================================================================


def _make_composition_object(
    resources: list[ComposedResource] | None = None,
) -> CompositionObject:
    from xptest.models import CompositionMode

    return CompositionObject(
        composition_name="test-comp",
        composition_path="/tmp/test-comp.yaml",
        xrd_name="test-xrd",
        xrd_path="/tmp/test-xrd.yaml",
        mode=CompositionMode.RESOURCES,
        resources=resources or [],
    )
