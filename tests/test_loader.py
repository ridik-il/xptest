"""Tests for the Composition loader (both Resources and Pipeline mode)."""

from __future__ import annotations

import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from xptest.loader import LoadError, load
from xptest.models import CompositionMode

_HERE = Path(__file__).parent
FIXTURES_DIR = _HERE.parent / "fixtures"
XRD_PATH = str(FIXTURES_DIR / "xrd.yaml")


def test_load_valid_resources_mode():
    comp_path = str(FIXTURES_DIR / "valid" / "vpc-subnet-iam.yaml")
    obj = load(comp_path, XRD_PATH)
    assert obj.mode == CompositionMode.RESOURCES
    assert len(obj.resources) == 3
    names = {r.name for r in obj.resources}
    assert names == {"main-vpc", "main-subnet", "vpc-role"}


def test_load_resources_mode_extracts_patches():
    comp_path = str(FIXTURES_DIR / "valid" / "vpc-subnet-iam.yaml")
    obj = load(comp_path, XRD_PATH)
    vpc = next(r for r in obj.resources if r.name == "main-vpc")
    assert len(vpc.patches) >= 1
    patch_types = {p.get("type", "FromCompositeFieldPath") for p in vpc.patches}
    assert "FromCompositeFieldPath" in patch_types or "ToCompositeFieldPath" in patch_types


def test_load_pipeline_mode(tmp_path: Path):
    """Minimal Pipeline mode composition must parse correctly."""
    xrd = tmp_path / "xrd.yaml"
    xrd.write_text(Path(XRD_PATH).read_text())

    comp = tmp_path / "comp.yaml"
    comp.write_text(
        textwrap.dedent("""
        apiVersion: apiextensions.crossplane.io/v1
        kind: Composition
        metadata:
          name: pipeline-test
        spec:
          compositeTypeRef:
            apiVersion: aws.example.org/v1alpha1
            kind: XVPCNetwork
          mode: Pipeline
          pipeline:
            - step: patch-and-transform
              functionRef:
                name: function-patch-and-transform
              input:
                apiVersion: pt.fn.crossplane.io/v1beta1
                kind: Resources
                resources:
                  - name: test-vpc
                    base:
                      apiVersion: ec2.aws.crossplane.io/v1beta1
                      kind: VPC
                      spec:
                        forProvider:
                          cidrBlock: "10.0.0.0/16"
                          region: "eu-west-1"
                    patches:
                      - type: FromCompositeFieldPath
                        fromFieldPath: spec.parameters.cidrBlock
                        toFieldPath: spec.forProvider.cidrBlock
        """)
    )

    obj = load(str(comp), str(xrd))
    assert obj.mode == CompositionMode.PIPELINE
    assert len(obj.resources) == 1
    assert obj.resources[0].name == "test-vpc"
    assert obj.resources[0].kind == "VPC"


def test_load_pipeline_mode_go_templating_inline(tmp_path: Path):
    """Constrained go-templating inline docs should be parsed as resources."""
    xrd = tmp_path / "xrd.yaml"
    xrd.write_text(Path(XRD_PATH).read_text())

    comp = tmp_path / "comp-go-template.yaml"
    comp.write_text(
        textwrap.dedent("""
        apiVersion: apiextensions.crossplane.io/v1
        kind: Composition
        metadata:
          name: pipeline-go-template-test
        spec:
          compositeTypeRef:
            apiVersion: aws.example.org/v1alpha1
            kind: XVPCNetwork
          mode: Pipeline
          pipeline:
            - step: role-and-policies
              functionRef:
                name: function-go-templating
              input:
                apiVersion: gotemplating.fn.crossplane.io/v1beta1
                kind: GoTemplate
                source: Inline
                inline:
                  template: |-
                    {{ $claimName := "demo" }}
                    ---
                    apiVersion: iam.aws.crossplane.io/v1beta1
                    kind: Role
                    metadata:
                      annotations:
                        gotemplating.fn.crossplane.io/composition-resource-name: role
                      name: {{$claimName}}-role
                    spec:
                      forProvider: {}
                    {{ if eq 1 1 }}
                    ---
                    apiVersion: iam.aws.crossplane.io/v1beta1
                    kind: Policy
                    metadata:
                      annotations:
                        gotemplating.fn.crossplane.io/composition-resource-name: default-policy
                    spec:
                      forProvider: {}
                    {{ end }}
        """)
    )

    obj = load(str(comp), str(xrd))
    assert obj.mode == CompositionMode.PIPELINE
    assert len(obj.resources) == 2

    names = {r.name for r in obj.resources}
    assert "role" in names
    assert "default-policy" in names

    kinds = {r.kind for r in obj.resources}
    assert kinds == {"Role", "Policy"}


def test_load_pipeline_mode_go_templating_fallback_name(tmp_path: Path):
    """Templated resource names should fall back to deterministic synthetic names."""
    xrd = tmp_path / "xrd.yaml"
    xrd.write_text(Path(XRD_PATH).read_text())

    comp = tmp_path / "comp-go-template-fallback.yaml"
    comp.write_text(
        textwrap.dedent("""
        apiVersion: apiextensions.crossplane.io/v1
        kind: Composition
        metadata:
          name: pipeline-go-template-fallback
        spec:
          compositeTypeRef:
            apiVersion: aws.example.org/v1alpha1
            kind: XVPCNetwork
          mode: Pipeline
          pipeline:
            - step: templated-name
              functionRef:
                name: function-go-templating
              input:
                apiVersion: gotemplating.fn.crossplane.io/v1beta1
                kind: GoTemplate
                source: Inline
                inline:
                  template: |-
                    ---
                    apiVersion: iam.aws.crossplane.io/v1beta1
                    kind: Policy
                    metadata:
                      name: {{$claimName}}-policy
                    spec:
                      forProvider: {}
        """)
    )

    obj = load(str(comp), str(xrd))
    assert obj.mode == CompositionMode.PIPELINE
    assert len(obj.resources) == 1
    assert obj.resources[0].name == "go-template-step-0-doc-0"
    assert obj.resources[0].kind == "Policy"


def test_load_pipeline_mode_from_crossplane_render(monkeypatch, tmp_path: Path):
    """When xr + functions are provided, resources are read from render output."""
    xrd = tmp_path / "xrd.yaml"
    xrd.write_text(Path(XRD_PATH).read_text())

    comp = tmp_path / "comp.yaml"
    comp.write_text(
        textwrap.dedent("""
        apiVersion: apiextensions.crossplane.io/v1
        kind: Composition
        metadata:
          name: render-test
        spec:
          compositeTypeRef:
            apiVersion: aws.example.org/v1alpha1
            kind: XVPCNetwork
          mode: Pipeline
          pipeline: []
        """)
    )

    xr = tmp_path / "xr.yaml"
    xr.write_text("apiVersion: aws.example.org/v1alpha1\nkind: XVPCNetwork\n")

    functions = tmp_path / "functions.yaml"
    functions.write_text("---\n")

    rendered = textwrap.dedent("""
    ---
    apiVersion: aws.example.org/v1alpha1
    kind: XVPCNetwork
    metadata:
      name: xr-sample
    ---
    apiVersion: iam.aws.crossplane.io/v1beta1
    kind: Role
    metadata:
      annotations:
        crossplane.io/composition-resource-name: role
      name: role-from-render
    spec:
      forProvider: {}
    ---
    apiVersion: kubernetes.crossplane.io/v1alpha1
    kind: Object
    metadata:
      annotations:
        gotemplating.fn.crossplane.io/composition-resource-name: service-account
    spec:
      forProvider: {}
    """)

    def _fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=rendered, stderr="")

    monkeypatch.setattr("xptest.loader.subprocess.run", _fake_run)

    obj = load(
        composition_path=str(comp),
        xrd_path=str(xrd),
        xr_path=str(xr),
        functions_path=str(functions),
    )

    assert obj.mode == CompositionMode.PIPELINE
    assert len(obj.resources) == 2
    assert {r.name for r in obj.resources} == {"role", "service-account"}


def test_load_pipeline_mode_render_error(monkeypatch, tmp_path: Path):
    """Render command failures should be surfaced as LoadError."""
    xrd = tmp_path / "xrd.yaml"
    xrd.write_text(Path(XRD_PATH).read_text())

    comp = tmp_path / "comp.yaml"
    comp.write_text(
        textwrap.dedent("""
        apiVersion: apiextensions.crossplane.io/v1
        kind: Composition
        metadata:
          name: render-test
        spec:
          compositeTypeRef:
            apiVersion: aws.example.org/v1alpha1
            kind: XVPCNetwork
          mode: Pipeline
          pipeline: []
        """)
    )

    xr = tmp_path / "xr.yaml"
    xr.write_text("apiVersion: aws.example.org/v1alpha1\nkind: XVPCNetwork\n")

    functions = tmp_path / "functions.yaml"
    functions.write_text("---\n")

    def _fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="render failed")

    monkeypatch.setattr("xptest.loader.subprocess.run", _fake_run)

    with pytest.raises(LoadError, match="crossplane render failed"):
        load(
            composition_path=str(comp),
            xrd_path=str(xrd),
            xr_path=str(xr),
            functions_path=str(functions),
        )


def test_load_wrong_kind_raises(tmp_path: Path):
    xrd = tmp_path / "xrd.yaml"
    xrd.write_text(Path(XRD_PATH).read_text())

    comp = tmp_path / "wrong.yaml"
    comp.write_text("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n")

    with pytest.raises(LoadError, match="expected kind=Composition"):
        load(str(comp), str(xrd))


def test_load_missing_file_raises():
    with pytest.raises(LoadError, match="File not found"):
        load("/nonexistent/composition.yaml", XRD_PATH)
