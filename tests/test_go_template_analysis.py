"""Tests for Go template expression extraction and L1-07 validation."""

from __future__ import annotations

from xptest.loader import extract_template_expressions
from xptest.models import ComposedResource, CompositionMode, CompositionObject


class TestExtractTemplateExpressions:
    def test_extracts_observed_composite_path(self):
        template = """
apiVersion: ec2.aws.upbound.io/v1beta1
kind: VPC
metadata:
  name: {{ .observed.composite.resource.metadata.name }}-vpc
spec:
  forProvider:
    region: {{ .observed.composite.resource.spec.region }}
    cidrBlock: {{ .observed.composite.resource.spec.cidrBlock }}
"""
        exprs = extract_template_expressions(template)
        assert "observed.composite.resource.metadata.name" in exprs
        assert "observed.composite.resource.spec.region" in exprs
        assert "observed.composite.resource.spec.cidrBlock" in exprs

    def test_skips_control_flow_lines(self):
        template = """
{{ if .observed.composite.resource.spec.enableDns }}
  enableDnsSupport: true
{{ end }}
"""
        exprs = extract_template_expressions(template)
        # Control flow expressions should still be extracted for field paths
        # but 'if' prefix is stripped
        assert len(exprs) == 0  # "if ..." is skipped as control

    def test_extracts_from_range_body(self):
        template = """
{{ range .observed.composite.resource.spec.subnets }}
  cidrBlock: {{ .cidr }}
{{ end }}
"""
        exprs = extract_template_expressions(template)
        # Single-segment .cidr is not a multi-segment dot path, so not extracted
        assert len(exprs) == 0

    def test_deduplicates_expressions(self):
        template = """
name: {{ .observed.composite.resource.spec.region }}
region: {{ .observed.composite.resource.spec.region }}
"""
        exprs = extract_template_expressions(template)
        assert exprs.count("observed.composite.resource.spec.region") == 1

    def test_empty_template(self):
        assert extract_template_expressions("") == []

    def test_no_template_expressions(self):
        template = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: static
"""
        assert extract_template_expressions(template) == []

    def test_desired_composite_path(self):
        template = """
status:
  id: {{ .desired.composite.resource.status.vpcId }}
"""
        exprs = extract_template_expressions(template)
        assert "desired.composite.resource.status.vpcId" in exprs


class TestL107TemplateVariableValidation:
    def _make_obj(self, template_expressions, xrd_params=None):
        xrd_spec = {}
        if xrd_params:
            xrd_spec = {
                "versions": [
                    {
                        "name": "v1alpha1",
                        "schema": {
                            "openAPIV3Schema": {
                                "properties": {
                                    "spec": {
                                        "properties": {
                                            k: {"type": "string"}
                                            for k in xrd_params
                                        }
                                    }
                                }
                            }
                        },
                    }
                ]
            }

        return CompositionObject(
            composition_name="test",
            composition_path="/tmp/test.yaml",
            xrd_name="test-xrd",
            xrd_path="/tmp/xrd.yaml",
            mode=CompositionMode.PIPELINE,
            resources=[
                ComposedResource(
                    name="vpc",
                    api_version="ec2.aws.upbound.io/v1beta1",
                    kind="VPC",
                    template_expressions=template_expressions,
                )
            ],
            xrd_spec=xrd_spec,
        )

    def test_warns_on_unknown_root(self):
        from xptest.layer1.static import _check_template_variables

        obj = self._make_obj(["invalidroot.something.else"])
        findings = _check_template_variables(obj)
        assert len(findings) == 1
        assert findings[0].rule == "L1-07/unknown-template-root"

    def test_no_warning_for_known_roots(self):
        from xptest.layer1.static import _check_template_variables

        obj = self._make_obj([
            "observed.composite.resource.spec.region",
            "desired.composite.resource.status.id",
            "spec.forProvider.region",
        ])
        findings = _check_template_variables(obj)
        assert len(findings) == 0

    def test_warns_on_unknown_xrd_parameter(self):
        from xptest.layer1.static import _check_template_variables

        obj = self._make_obj(
            ["observed.composite.resource.spec.nonExistentParam"],
            xrd_params=["region", "cidrBlock"],
        )
        findings = _check_template_variables(obj)
        assert any(f.rule == "L1-07/unknown-xrd-parameter" for f in findings)

    def test_no_warning_for_valid_xrd_parameter(self):
        from xptest.layer1.static import _check_template_variables

        obj = self._make_obj(
            ["observed.composite.resource.spec.region"],
            xrd_params=["region", "cidrBlock"],
        )
        findings = _check_template_variables(obj)
        xrd_findings = [f for f in findings if f.rule == "L1-07/unknown-xrd-parameter"]
        assert len(xrd_findings) == 0

    def test_no_warning_without_xrd_params(self):
        from xptest.layer1.static import _check_template_variables

        obj = self._make_obj(
            ["observed.composite.resource.spec.anything"],
        )
        findings = _check_template_variables(obj)
        xrd_findings = [f for f in findings if f.rule == "L1-07/unknown-xrd-parameter"]
        assert len(xrd_findings) == 0

    def test_empty_expressions_no_findings(self):
        from xptest.layer1.static import _check_template_variables

        obj = self._make_obj([])
        findings = _check_template_variables(obj)
        assert len(findings) == 0
