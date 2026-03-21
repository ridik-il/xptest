"""Tests for the Composition loader (both Resources and Pipeline mode)."""

from __future__ import annotations

import textwrap
from pathlib import Path

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
