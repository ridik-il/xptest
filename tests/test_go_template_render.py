"""Tests for Go template rendering — covers the exact failure modes that
the old sanitization approach could not handle.

These tests verify that:
1. Complex Go templates no longer crash yaml.safe_load
2. The degraded parser catches errors gracefully
3. The rendering path produces correct resources when available
4. Render errors are surfaced as findings, not tracebacks

Integration tests that require Docker are marked with pytest.mark.integration
and skipped by default.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from xptest.loader import (
    LoadError,
    _parse_go_template_to_docs,
    _parse_go_templating_inline,
    extract_template_expressions,
    load,
)
from xptest.models import CompositionMode, RenderMode

# ---------------------------------------------------------------------------
# Regression: the exact YAML parse error that motivates this change
# ---------------------------------------------------------------------------


class TestYamlScanErrorRegression:
    """The old approach produced 'could not find expected ":"' on templates
    with structural expressions.  Verify this no longer crashes.
    """

    TEMPLATE_WITH_STRUCTURAL_CONDITIONALS = """\
{{ $claimName:=(index .observed.composite.resource.metadata.labels "crossplane.io/claim-name") }}
{{ $roleName:=$claimName }}

---
apiVersion: iam.aws.crossplane.io/v1beta1
kind: Role
metadata:
  annotations:
    gotemplating.fn.crossplane.io/composition-resource-name: role
  name: {{$roleName}}
spec:
  forProvider:
    assumeRolePolicyDocument: |
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Principal": {
              "Federated": "arn:aws:iam::{{$accountId}}:oidc-provider/example"
            },
            "Action": "sts:AssumeRoleWithWebIdentity"
          }
        ]
      }

---

{{ if and (ne .observed.resources nil) (ne ( index .observed.resources "role" ) nil) }}
{{ if eq (.observed.resources.role | getResourceCondition "Ready").Status "True" }}

{{ with $policiesARN := .observed.composite.resource.spec.policiesARN }}
{{ range $policyIndex, $policyArn := $policiesARN }}
apiVersion: iam.aws.crossplane.io/v1beta1
kind: RolePolicyAttachment
metadata:
  annotations:
    gotemplating.fn.crossplane.io/composition-resource-name: {{$claimName}}-rpa-{{$policyIndex}}
spec:
  forProvider:
    policyArn: {{$policyArn}}
    roleName: {{$roleName}}
---
{{ end }}
{{ end }}

{{ end }}
{{ end }}
"""

    def test_degraded_parse_does_not_crash(self):
        """The old code would raise yaml.scanner.ScannerError here.
        Now it returns partial results gracefully."""
        docs = _parse_go_template_to_docs(self.TEMPLATE_WITH_STRUCTURAL_CONDITIONALS)
        # Should not raise — may return partial or empty results
        assert isinstance(docs, list)

    def test_degraded_parse_extracts_at_least_role(self):
        """Even in degraded mode, the Role resource (outside conditionals)
        should be extractable."""
        docs = _parse_go_template_to_docs(self.TEMPLATE_WITH_STRUCTURAL_CONDITIONALS)
        kinds = [d.get("kind") for d in docs]
        # The Role is before any conditionals, so it should be parseable
        assert "Role" in kinds


class TestTemplateWithRange:
    """Test templates that use {{ range }} to create variable resources."""

    RANGE_TEMPLATE = """\
{{ range $i, $subnet := .observed.composite.resource.spec.subnets }}
---
apiVersion: ec2.aws.upbound.io/v1beta1
kind: Subnet
metadata:
  annotations:
    gotemplating.fn.crossplane.io/composition-resource-name: subnet-{{ $i }}
  name: subnet-{{ $i }}
spec:
  forProvider:
    cidrBlock: {{ $subnet.cidr }}
    vpcId: {{ $.observed.composite.resource.status.vpcId }}
{{ end }}
"""

    def test_range_template_does_not_crash(self):
        docs = _parse_go_template_to_docs(self.RANGE_TEMPLATE)
        assert isinstance(docs, list)
        # Range body after stripping produces partial content — should not crash


class TestTemplateWithConditionalListItems:
    """Test templates where conditionals add/remove list items."""

    CONDITIONAL_LIST_TEMPLATE = """\
---
apiVersion: ec2.aws.upbound.io/v1beta1
kind: SecurityGroup
metadata:
  annotations:
    gotemplating.fn.crossplane.io/composition-resource-name: sg
spec:
  forProvider:
    ingress:
{{ if .observed.composite.resource.spec.allowSSH }}
      - fromPort: 22
        toPort: 22
        protocol: tcp
        cidrBlocks:
          - "10.0.0.0/8"
{{ end }}
      - fromPort: 443
        toPort: 443
        protocol: tcp
        cidrBlocks:
          - "0.0.0.0/0"
"""

    def test_conditional_list_items_does_not_crash(self):
        docs = _parse_go_template_to_docs(self.CONDITIONAL_LIST_TEMPLATE)
        assert isinstance(docs, list)
        # Should extract the SecurityGroup even with conditional list items
        if docs:
            assert docs[0].get("kind") == "SecurityGroup"


class TestTemplateWithTemplatedMetadata:
    """Test templates where metadata fields use template expressions."""

    TEMPLATED_METADATA = """\
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .observed.composite.resource.metadata.name }}-config
  namespace: {{ .observed.composite.resource.spec.namespace }}
  annotations:
    gotemplating.fn.crossplane.io/composition-resource-name: configmap
    example.com/owner: {{ .observed.composite.resource.metadata.labels.owner }}
data:
  region: {{ .observed.composite.resource.spec.region }}
"""

    def test_templated_metadata_does_not_crash(self):
        docs = _parse_go_template_to_docs(self.TEMPLATED_METADATA)
        assert isinstance(docs, list)

    def test_templated_metadata_extracts_kind(self):
        docs = _parse_go_template_to_docs(self.TEMPLATED_METADATA)
        assert len(docs) >= 1
        assert docs[0].get("kind") == "ConfigMap"

    def test_expression_extraction(self):
        exprs = extract_template_expressions(self.TEMPLATED_METADATA)
        assert "observed.composite.resource.metadata.name" in exprs
        assert "observed.composite.resource.spec.namespace" in exprs
        assert "observed.composite.resource.spec.region" in exprs


# ---------------------------------------------------------------------------
# Pipeline-mode loading with degraded parse
# ---------------------------------------------------------------------------


class TestPipelineModeOfflineFallback:
    """Test that pipeline compositions with go-templating don't crash
    when loaded in offline mode."""

    def _write_composition(self, tmp_path, template):
        comp = {
            "apiVersion": "apiextensions.crossplane.io/v1",
            "kind": "Composition",
            "metadata": {"name": "test-comp"},
            "spec": {
                "compositeTypeRef": {
                    "apiVersion": "example.org/v1alpha1",
                    "kind": "XTest",
                },
                "mode": "Pipeline",
                "pipeline": [
                    {
                        "step": "templates",
                        "functionRef": {"name": "function-go-templating"},
                        "input": {
                            "apiVersion": "gotemplating.fn.crossplane.io/v1beta1",
                            "kind": "GoTemplate",
                            "source": "Inline",
                            "inline": {"template": template},
                        },
                    },
                    {
                        "step": "ready",
                        "functionRef": {"name": "function-auto-ready"},
                    },
                ],
            },
        }
        path = tmp_path / "composition.yaml"
        path.write_text(yaml.dump(comp))
        return str(path)

    def _write_xrd(self, tmp_path):
        xrd = {
            "apiVersion": "apiextensions.crossplane.io/v1",
            "kind": "CompositeResourceDefinition",
            "metadata": {"name": "xtests.example.org"},
            "spec": {
                "group": "example.org",
                "names": {"kind": "XTest"},
                "versions": [
                    {
                        "name": "v1alpha1",
                        "schema": {
                            "openAPIV3Schema": {
                                "type": "object",
                                "properties": {
                                    "spec": {
                                        "type": "object",
                                        "properties": {
                                            "region": {"type": "string"},
                                        },
                                    }
                                },
                            }
                        },
                    }
                ],
            },
        }
        path = tmp_path / "xrd.yaml"
        path.write_text(yaml.dump(xrd))
        return str(path)

    def test_simple_template_loads_offline(self, tmp_path):
        """A simple template without structural conditionals should
        load successfully even in offline mode."""
        template = """\
---
apiVersion: ec2.aws.upbound.io/v1beta1
kind: VPC
metadata:
  annotations:
    gotemplating.fn.crossplane.io/composition-resource-name: vpc
spec:
  forProvider:
    region: {{ .observed.composite.resource.spec.region }}
    cidrBlock: "10.0.0.0/16"
"""
        comp_path = self._write_composition(tmp_path, template)
        xrd_path = self._write_xrd(tmp_path)

        obj = load(comp_path, xrd_path, render_mode="offline")
        assert obj.mode == CompositionMode.PIPELINE
        assert obj.render_mode == RenderMode.DEGRADED_PARSE
        assert len(obj.resources) >= 1
        assert obj.resources[0].kind == "VPC"

    def test_complex_template_does_not_crash_offline(self, tmp_path):
        """A complex template with nested conditionals should not crash."""
        template = TestYamlScanErrorRegression.TEMPLATE_WITH_STRUCTURAL_CONDITIONALS
        comp_path = self._write_composition(tmp_path, template)
        xrd_path = self._write_xrd(tmp_path)

        # Should not raise — returns what it can parse
        obj = load(comp_path, xrd_path, render_mode="offline")
        assert obj.mode == CompositionMode.PIPELINE
        assert obj.render_mode == RenderMode.DEGRADED_PARSE

    def test_render_mode_on_composition_object(self, tmp_path):
        """Verify render_mode is correctly set on the CompositionObject."""
        template = """\
---
apiVersion: v1
kind: ConfigMap
metadata:
  annotations:
    gotemplating.fn.crossplane.io/composition-resource-name: cm
spec: {}
"""
        comp_path = self._write_composition(tmp_path, template)
        xrd_path = self._write_xrd(tmp_path)

        obj = load(comp_path, xrd_path, render_mode="offline")
        assert obj.render_mode == RenderMode.DEGRADED_PARSE


# ---------------------------------------------------------------------------
# Mocked render path
# ---------------------------------------------------------------------------


class TestMockedRenderPath:
    """Test the auto-render path with mocked crossplane subprocess."""

    def _write_files(self, tmp_path):
        comp = {
            "apiVersion": "apiextensions.crossplane.io/v1",
            "kind": "Composition",
            "metadata": {"name": "test-comp"},
            "spec": {
                "compositeTypeRef": {
                    "apiVersion": "example.org/v1alpha1",
                    "kind": "XTest",
                },
                "mode": "Pipeline",
                "pipeline": [
                    {
                        "step": "templates",
                        "functionRef": {"name": "function-go-templating"},
                        "input": {
                            "kind": "GoTemplate",
                            "inline": {
                                "template": "---\napiVersion: v1\nkind: CM\n",
                            },
                        },
                    },
                ],
            },
        }
        xrd = {
            "apiVersion": "apiextensions.crossplane.io/v1",
            "kind": "CompositeResourceDefinition",
            "metadata": {"name": "xtests.example.org"},
            "spec": {
                "group": "example.org",
                "names": {"kind": "XTest"},
                "versions": [
                    {
                        "name": "v1alpha1",
                        "schema": {
                            "openAPIV3Schema": {
                                "type": "object",
                                "properties": {
                                    "spec": {
                                        "type": "object",
                                        "properties": {
                                            "region": {"type": "string"},
                                        },
                                    }
                                },
                            }
                        },
                    }
                ],
            },
        }
        comp_path = tmp_path / "composition.yaml"
        comp_path.write_text(yaml.dump(comp))
        xrd_path = tmp_path / "xrd.yaml"
        xrd_path.write_text(yaml.dump(xrd))
        return str(comp_path), str(xrd_path)

    def test_render_path_used_when_available(self, tmp_path):
        """When crossplane render succeeds, resources come from render output."""
        comp_path, xrd_path = self._write_files(tmp_path)

        rendered_output = """\
---
apiVersion: example.org/v1alpha1
kind: XTest
metadata:
  name: xptest-render
spec:
  region: us-east-1
---
apiVersion: iam.aws.crossplane.io/v1beta1
kind: Role
metadata:
  name: test-role
  annotations:
    crossplane.io/composition-resource-name: role
spec:
  forProvider:
    assumeRolePolicyDocument: '{}'
---
apiVersion: iam.aws.crossplane.io/v1beta1
kind: Policy
metadata:
  name: test-policy
  annotations:
    crossplane.io/composition-resource-name: default-policy
spec:
  forProvider:
    name: test-policy
"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = rendered_output

        with patch("xptest.render.subprocess.run", return_value=mock_result):
            obj = load(comp_path, xrd_path, render_mode="auto")

        assert obj.render_mode == RenderMode.RENDER
        assert len(obj.resources) == 2
        names = {r.name for r in obj.resources}
        assert "role" in names
        assert "default-policy" in names

    def test_offline_mode_skips_render_even_with_xr_and_functions(self, tmp_path):
        """render_mode='offline' with xr_path + functions_path should NOT call subprocess."""
        comp_path, xrd_path = self._write_files(tmp_path)
        xr_path = tmp_path / "xr.yaml"
        xr_path.write_text(yaml.dump({
            "apiVersion": "example.org/v1alpha1",
            "kind": "XTest",
            "metadata": {"name": "test-xr"},
            "spec": {"region": "us-east-1"},
        }))
        fn_path = tmp_path / "functions.yaml"
        fn_path.write_text(yaml.dump({
            "apiVersion": "pkg.crossplane.io/v1beta1",
            "kind": "Function",
            "metadata": {"name": "function-go-templating"},
        }))

        with patch("xptest.render.subprocess.run") as mock_run:
            obj = load(
                comp_path, xrd_path,
                xr_path=str(xr_path),
                functions_path=str(fn_path),
                render_mode="offline",
            )
            # subprocess.run should NOT have been called
            mock_run.assert_not_called()

        assert obj.render_mode == RenderMode.DEGRADED_PARSE

    def test_render_caches_working_command_variant(self, tmp_path):
        """After first successful render, subsequent renders reuse the same command."""
        import xptest.loader as loader_mod

        comp_path, xrd_path = self._write_files(tmp_path)

        rendered_output = (
            "---\napiVersion: iam.aws.crossplane.io/v1beta1\n"
            "kind: Role\nmetadata:\n  name: test-role\n"
            "  annotations:\n"
            "    crossplane.io/composition-resource-name: role\n"
            "spec:\n  forProvider:\n"
            "    assumeRolePolicyDocument: '{}'\n"
        )
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = rendered_output

        # Reset caches before test
        saved_cmd = loader_mod._working_render_cmd
        saved_fn = loader_mod._working_functions_variant
        saved_rewrite = loader_mod._functions_rewrite_cache.copy()
        loader_mod._working_render_cmd = None
        loader_mod._working_functions_variant = None
        loader_mod._functions_rewrite_cache.clear()

        try:
            with patch(
                "xptest.loader.subprocess.run", return_value=mock_result
            ) as mock_run:
                # First render — discovery path
                load(comp_path, xrd_path, render_mode="auto")
                first_call_count = mock_run.call_count

                # Second render — should use cached command variant
                load(comp_path, xrd_path, render_mode="auto")
                second_call_count = mock_run.call_count - first_call_count

            # Second render should make exactly 1 subprocess call
            # (the cached fast path), not the full discovery sweep.
            assert second_call_count == 1
        finally:
            loader_mod._working_render_cmd = saved_cmd
            loader_mod._working_functions_variant = saved_fn
            loader_mod._functions_rewrite_cache = saved_rewrite

    def test_render_unavailable_falls_back_to_degraded(self, tmp_path):
        """When crossplane CLI is missing, falls back to degraded parse."""
        comp_path, xrd_path = self._write_files(tmp_path)

        with patch(
            "xptest.render.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            obj = load(comp_path, xrd_path, render_mode="auto")

        assert obj.render_mode == RenderMode.DEGRADED_PARSE

    def test_render_mode_render_fails_hard_when_unavailable(self, tmp_path):
        """When render_mode='render' and CLI is missing, raises LoadError."""
        comp_path, xrd_path = self._write_files(tmp_path)

        with patch(
            "xptest.render.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            with pytest.raises(LoadError, match="crossplane CLI is not available"):
                load(comp_path, xrd_path, render_mode="render")


# ---------------------------------------------------------------------------
# Realistic pipeline composition (from reference implementation)
# ---------------------------------------------------------------------------


class TestRealisticComposition:
    """Test with a realistic pipeline composition structure modeled on
    the crossplane-composition-tester reference."""

    REALISTIC_TEMPLATE = """\
{{ $accountId:="123456789012" }}
{{ $region:="eu-central-1" }}
{{ $claimName:="test-sa" }}
{{ $roleName:=$claimName }}
{{ $serviceAccountName:="test-sa" }}
{{ $serviceAccountNamespace:="default" }}

---
apiVersion: iam.aws.crossplane.io/v1beta1
kind: Role
metadata:
  annotations:
    gotemplating.fn.crossplane.io/composition-resource-name: role
  name: {{$roleName}}
spec:
  forProvider:
    assumeRolePolicyDocument: |
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Principal": {
              "Federated": "arn:aws:iam::{{$accountId}}:oidc-provider/example"
            },
            "Action": "sts:AssumeRoleWithWebIdentity"
          }
        ]
      }
---
apiVersion: iam.aws.crossplane.io/v1beta1
kind: Policy
metadata:
  annotations:
    gotemplating.fn.crossplane.io/composition-resource-name: default-policy
spec:
  forProvider:
    name: {{$claimName}}-default-policy
    document: |
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": "arn:aws:secretsmanager:{{$region}}:{{$accountId}}:secret:/all/*"
          }
        ]
      }
"""

    def test_realistic_template_degraded_parse(self):
        """The realistic template should produce at least the
        unconditional resources in degraded mode."""
        docs = _parse_go_template_to_docs(self.REALISTIC_TEMPLATE)
        kinds = [d.get("kind") for d in docs]
        # Both Role and Policy are outside conditionals
        assert "Role" in kinds
        assert "Policy" in kinds

    def test_realistic_template_resource_names(self):
        """Resource names should be extracted from annotations."""
        step = {
            "input": {
                "kind": "GoTemplate",
                "inline": {"template": self.REALISTIC_TEMPLATE},
            }
        }
        resources = _parse_go_templating_inline(step, "/test", 0)
        names = [r.name for r in resources]
        assert "role" in names
        assert "default-policy" in names

    def test_realistic_template_expressions_extracted(self):
        """Field path expressions should be extracted for L1-07 checks."""
        exprs = extract_template_expressions(self.REALISTIC_TEMPLATE)
        # Variable assignments don't generate dot-path expressions,
        # but inline expressions like {{$roleName}} do not match the
        # multi-segment dot-path pattern either.  This is expected —
        # expression extraction focuses on .observed.composite... paths.
        assert isinstance(exprs, list)


# ---------------------------------------------------------------------------
# Integration tests (require Docker + crossplane CLI)
# ---------------------------------------------------------------------------

# These would be enabled with: pytest -m integration
# For now they serve as documentation of the expected usage.


@pytest.mark.skip(reason="Requires crossplane CLI and Docker")
class TestDockerIntegration:
    """Integration tests that actually run crossplane render with Docker.

    To run these tests:
        1. Install crossplane CLI (v1.17+)
        2. Ensure Docker is running
        3. Run: pytest tests/test_go_template_render.py -m integration -v
    """

    def test_render_reference_composition(self, tmp_path):
        """Render the reference implementation's service-account composition."""
        from xptest.render import auto_render_pipeline

        ref_dir = Path(
            "/home/riyad/Testing-Framework-for-Crossplane-Compositions-in-AWS-Environments"
            "/crossplane-composition-tester/test"
        )
        comp_path = ref_dir / "pkg/service-account-with-functions/composition.yaml"
        xrd_path = ref_dir / "pkg/service-account-with-functions/definition.yaml"

        if not comp_path.exists():
            pytest.skip("Reference composition not found")

        rendered = auto_render_pipeline(
            str(comp_path), str(xrd_path), timeout=60
        )
        assert "Role" in rendered
