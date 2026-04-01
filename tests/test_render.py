"""Tests for the render module — XR generation, functions generation, output parsing."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import yaml

from xptest.render import (
    RenderError,
    RenderUnavailable,
    _generate_spec_defaults,
    generate_functions_yaml,
    generate_xr_from_xrd,
    has_go_templating_steps,
    render_composition,
)

# ---------------------------------------------------------------------------
# generate_xr_from_xrd
# ---------------------------------------------------------------------------


class TestGenerateXrFromXrd:
    def _xrd(self, properties=None, required=None):
        spec_schema = {"type": "object"}
        if properties:
            spec_schema["properties"] = properties
        if required:
            spec_schema["required"] = required
        return {
            "apiVersion": "apiextensions.crossplane.io/v1",
            "kind": "CompositeResourceDefinition",
            "metadata": {"name": "xnetworks.example.org"},
            "spec": {
                "group": "example.org",
                "names": {"kind": "XNetwork"},
                "versions": [
                    {
                        "name": "v1alpha1",
                        "schema": {
                            "openAPIV3Schema": {
                                "type": "object",
                                "properties": {"spec": spec_schema},
                            }
                        },
                    }
                ],
            },
        }

    def _comp(self):
        return {
            "spec": {
                "compositeTypeRef": {
                    "apiVersion": "example.org/v1alpha1",
                    "kind": "XNetwork",
                }
            }
        }

    def test_basic_xr_generation(self):
        xr = generate_xr_from_xrd(self._xrd(), self._comp())
        assert xr["apiVersion"] == "example.org/v1alpha1"
        assert xr["kind"] == "XNetwork"
        assert xr["metadata"]["name"] == "xptest-render"
        assert "crossplane.io/claim-name" in xr["metadata"]["labels"]

    def test_string_field_defaults(self):
        xr = generate_xr_from_xrd(
            self._xrd(
                properties={
                    "region": {"type": "string"},
                    "name": {"type": "string"},
                    "namespace": {"type": "string"},
                }
            ),
            self._comp(),
        )
        assert xr["spec"]["region"] == "us-east-1"
        assert "xptest" in xr["spec"]["name"]
        assert xr["spec"]["namespace"] == "default"

    def test_boolean_field_defaults(self):
        xr = generate_xr_from_xrd(
            self._xrd(properties={"enabled": {"type": "boolean"}}),
            self._comp(),
        )
        assert xr["spec"]["enabled"] is False

    def test_integer_field_defaults(self):
        xr = generate_xr_from_xrd(
            self._xrd(properties={"count": {"type": "integer", "minimum": 3}}),
            self._comp(),
        )
        assert xr["spec"]["count"] == 3

    def test_enum_field_uses_first_value(self):
        xr = generate_xr_from_xrd(
            self._xrd(
                properties={
                    "tier": {
                        "type": "string",
                        "enum": ["small", "medium", "large"],
                    }
                }
            ),
            self._comp(),
        )
        assert xr["spec"]["tier"] == "small"

    def test_array_field_defaults_empty(self):
        xr = generate_xr_from_xrd(
            self._xrd(properties={"tags": {"type": "array", "items": {"type": "string"}}}),
            self._comp(),
        )
        assert xr["spec"]["tags"] == []

    def test_generated_xr_is_valid_yaml(self):
        xr = generate_xr_from_xrd(
            self._xrd(
                properties={
                    "region": {"type": "string"},
                    "count": {"type": "integer"},
                    "enabled": {"type": "boolean"},
                }
            ),
            self._comp(),
        )
        # Must round-trip through YAML without error
        dumped = yaml.dump(xr)
        loaded = yaml.safe_load(dumped)
        assert loaded["kind"] == "XNetwork"


# ---------------------------------------------------------------------------
# generate_functions_yaml
# ---------------------------------------------------------------------------


class TestGenerateFunctionsYaml:
    def test_generates_from_pipeline_steps(self):
        comp = {
            "spec": {
                "pipeline": [
                    {"step": "templates", "functionRef": {"name": "function-go-templating"}},
                    {"step": "ready", "functionRef": {"name": "function-auto-ready"}},
                ]
            }
        }
        funcs = generate_functions_yaml(comp)
        assert len(funcs) == 2
        assert funcs[0]["metadata"]["name"] == "function-go-templating"
        assert "go-templating" in funcs[0]["spec"]["package"]
        assert funcs[1]["metadata"]["name"] == "function-auto-ready"

    def test_deduplicates_function_refs(self):
        comp = {
            "spec": {
                "pipeline": [
                    {"step": "a", "functionRef": {"name": "function-go-templating"}},
                    {"step": "b", "functionRef": {"name": "function-go-templating"}},
                ]
            }
        }
        funcs = generate_functions_yaml(comp)
        assert len(funcs) == 1

    def test_unknown_function_gets_placeholder(self):
        comp = {
            "spec": {
                "pipeline": [
                    {"step": "x", "functionRef": {"name": "my-custom-function"}},
                ]
            }
        }
        funcs = generate_functions_yaml(comp)
        assert len(funcs) == 1
        assert "unknown" in funcs[0]["spec"]["package"]

    def test_empty_pipeline(self):
        comp = {"spec": {"pipeline": []}}
        assert generate_functions_yaml(comp) == []

    def test_generated_yaml_is_valid(self):
        comp = {
            "spec": {
                "pipeline": [
                    {"step": "t", "functionRef": {"name": "function-go-templating"}},
                ]
            }
        }
        funcs = generate_functions_yaml(comp)
        dumped = yaml.dump_all(funcs)
        loaded = list(yaml.safe_load_all(dumped))
        assert len(loaded) == 1
        assert loaded[0]["kind"] == "Function"


# ---------------------------------------------------------------------------
# has_go_templating_steps
# ---------------------------------------------------------------------------


class TestHasGoTemplatingSteps:
    def test_detects_gotemplate_kind(self):
        comp = {
            "spec": {
                "pipeline": [
                    {
                        "step": "templates",
                        "functionRef": {"name": "function-go-templating"},
                        "input": {"kind": "GoTemplate"},
                    }
                ]
            }
        }
        assert has_go_templating_steps(comp) is True

    def test_detects_function_name_pattern(self):
        comp = {
            "spec": {
                "pipeline": [
                    {
                        "step": "t",
                        "functionRef": {"name": "function-go-templating"},
                    }
                ]
            }
        }
        assert has_go_templating_steps(comp) is True

    def test_no_go_templating(self):
        comp = {
            "spec": {
                "pipeline": [
                    {
                        "step": "pat",
                        "functionRef": {"name": "function-patch-and-transform"},
                        "input": {"kind": "Resources"},
                    }
                ]
            }
        }
        assert has_go_templating_steps(comp) is False


# ---------------------------------------------------------------------------
# render_composition (mocked subprocess)
# ---------------------------------------------------------------------------


class TestRenderComposition:
    def test_successful_render(self):
        rendered_yaml = """---
apiVersion: iam.aws.crossplane.io/v1beta1
kind: Role
metadata:
  name: test-role
  annotations:
    crossplane.io/composition-resource-name: role
spec:
  forProvider:
    assumeRolePolicyDocument: '{}'
"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = rendered_yaml

        with patch("xptest.render.subprocess.run", return_value=mock_result):
            output = render_composition(
                composition_path="/tmp/comp.yaml",
                xr_yaml="apiVersion: v1\nkind: Test\n",
                functions_yaml="apiVersion: v1\nkind: Function\n",
            )
            assert "Role" in output

    def test_crossplane_not_found_raises(self):
        with patch(
            "xptest.render.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            try:
                render_composition("/tmp/comp.yaml", "xr", "funcs")
                assert False, "Should have raised"
            except RenderUnavailable:
                pass

    def test_render_error_raises(self):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "template error: nil pointer"
        mock_result.stdout = ""

        with patch("xptest.render.subprocess.run", return_value=mock_result):
            try:
                render_composition("/tmp/comp.yaml", "xr", "funcs")
                assert False, "Should have raised"
            except RenderError as exc:
                assert "nil pointer" in exc.stderr

    def test_timeout_raises(self):
        import subprocess as sp

        with patch(
            "xptest.render.subprocess.run",
            side_effect=sp.TimeoutExpired("cmd", 10),
        ):
            try:
                render_composition("/tmp/comp.yaml", "xr", "funcs")
                assert False, "Should have raised"
            except RenderError:
                pass


# ---------------------------------------------------------------------------
# _generate_spec_defaults
# ---------------------------------------------------------------------------


class TestGenerateSpecDefaults:
    def test_nested_object_properties(self):
        schema = {
            "properties": {
                "networking": {
                    "type": "object",
                    "properties": {
                        "vpcCidr": {"type": "string"},
                        "enableDns": {"type": "boolean"},
                    },
                }
            }
        }
        defaults = _generate_spec_defaults(schema)
        assert isinstance(defaults["networking"], dict)
        assert defaults["networking"]["enableDns"] is False

    def test_default_value_used(self):
        schema = {"properties": {"region": {"type": "string", "default": "eu-west-1"}}}
        defaults = _generate_spec_defaults(schema)
        assert defaults["region"] == "eu-west-1"
