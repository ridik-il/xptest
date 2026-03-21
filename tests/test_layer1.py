"""Tests for Layer 1 — Static Validation."""

from __future__ import annotations

from pathlib import Path

from xptest.layer1 import static as layer1
from xptest.loader import load
from xptest.models import Severity

_HERE = Path(__file__).parent
FIXTURES_DIR = _HERE.parent / "fixtures"
XRD_PATH = str(FIXTURES_DIR / "xrd.yaml")
SAMPLE_BUNDLE = str(_HERE.parent / "schemas" / "sample-bundle")


def _load_valid(crd_bundle: str = "") -> object:
    return load(
        str(FIXTURES_DIR / "valid" / "vpc-subnet-iam.yaml"),
        XRD_PATH,
        crd_bundle_path=crd_bundle,
    )


def test_valid_composition_no_findings():
    obj = _load_valid()
    findings = layer1.run(obj)
    assert findings == [], f"Expected no findings, got: {findings}"


def test_no_duplicate_names_in_valid():
    obj = _load_valid()
    dup_findings = [f for f in layer1.run(obj) if f.rule == "L1-03/duplicate-resource-name"]
    assert dup_findings == []


def test_duplicate_name_detected(tmp_path):
    import textwrap
    from pathlib import Path

    xrd = tmp_path / "xrd.yaml"
    xrd.write_text(Path(XRD_PATH).read_text())

    comp = tmp_path / "dup.yaml"
    comp.write_text(
        textwrap.dedent("""
        apiVersion: apiextensions.crossplane.io/v1
        kind: Composition
        metadata:
          name: dup-test
        spec:
          compositeTypeRef:
            apiVersion: aws.example.org/v1alpha1
            kind: XVPCNetwork
          mode: Resources
          resources:
            - name: main-vpc
              base:
                apiVersion: ec2.aws.crossplane.io/v1beta1
                kind: VPC
                spec:
                  forProvider:
                    cidrBlock: "10.0.0.0/16"
                    region: "eu-west-1"
            - name: main-vpc
              base:
                apiVersion: ec2.aws.crossplane.io/v1beta1
                kind: VPC
                spec:
                  forProvider:
                    cidrBlock: "10.0.1.0/24"
                    region: "eu-west-1"
        """)
    )

    obj = load(str(comp), str(xrd))
    findings = layer1.run(obj)
    dup = [f for f in findings if f.rule == "L1-03/duplicate-resource-name"]
    assert len(dup) >= 1
    assert dup[0].severity == Severity.CRITICAL


def test_invalid_field_path_detected(tmp_path):
    import textwrap
    from pathlib import Path

    xrd = tmp_path / "xrd.yaml"
    xrd.write_text(Path(XRD_PATH).read_text())

    comp = tmp_path / "bad_path.yaml"
    comp.write_text(
        textwrap.dedent("""
        apiVersion: apiextensions.crossplane.io/v1
        kind: Composition
        metadata:
          name: bad-path-test
        spec:
          compositeTypeRef:
            apiVersion: aws.example.org/v1alpha1
            kind: XVPCNetwork
          mode: Resources
          resources:
            - name: main-vpc
              base:
                apiVersion: ec2.aws.crossplane.io/v1beta1
                kind: VPC
                spec:
                  forProvider:
                    cidrBlock: "10.0.0.0/16"
                    region: "eu-west-1"
              patches:
                - type: FromCompositeFieldPath
                  fromFieldPath: ""
                  toFieldPath: spec.forProvider.cidrBlock
        """)
    )

    obj = load(str(comp), str(xrd))
    findings = layer1.run(obj)
    bad = [f for f in findings if f.rule == "L1-02/invalid-field-path"]
    assert len(bad) >= 1
    assert bad[0].severity == Severity.CRITICAL


def test_provider_lock_unknown_kind_warns(tmp_path):
    import textwrap
    from pathlib import Path

    xrd = tmp_path / "xrd.yaml"
    xrd.write_text(Path(XRD_PATH).read_text())

    comp = tmp_path / "unknown_kind.yaml"
    comp.write_text(
        textwrap.dedent("""
        apiVersion: apiextensions.crossplane.io/v1
        kind: Composition
        metadata:
          name: unknown-kind-test
        spec:
          compositeTypeRef:
            apiVersion: aws.example.org/v1alpha1
            kind: XVPCNetwork
          mode: Resources
          resources:
            - name: my-resource
              base:
                apiVersion: s3.aws.crossplane.io/v1beta1
                kind: Bucket
                spec:
                  forProvider:
                    region: "eu-west-1"
        """)
    )

    obj = load(str(comp), str(xrd), crd_bundle_path=SAMPLE_BUNDLE)
    findings = layer1.run(obj)
    lock = [f for f in findings if f.rule == "L1-04/unknown-provider-kind"]
    assert len(lock) >= 1
    assert lock[0].severity == Severity.WARNING


def test_schema_oneof_violation_detected(tmp_path):
    import textwrap
    from pathlib import Path

    xrd = tmp_path / "xrd.yaml"
    xrd.write_text(Path(XRD_PATH).read_text())

    comp = tmp_path / "oneof_violation.yaml"
    comp.write_text(
        textwrap.dedent("""
        apiVersion: apiextensions.crossplane.io/v1
        kind: Composition
        metadata:
          name: oneof-violation-test
        spec:
          compositeTypeRef:
            apiVersion: aws.example.org/v1alpha1
            kind: XVPCNetwork
          mode: Resources
          resources:
            - name: main-db
              base:
                apiVersion: rds.aws.crossplane.io/v1beta1
                kind: DBInstance
                spec:
                  forProvider:
                    dbInstanceClass: db.t3.micro
                    engine: postgres
                    region: eu-west-1
                    dbSubnetGroupName: manual-subnet-group
                    dbSubnetGroupNameRef:
                      name: referenced-subnet-group
        """)
    )

    obj = load(str(comp), str(xrd), crd_bundle_path=SAMPLE_BUNDLE)
    findings = layer1.run(obj)
    schema = [f for f in findings if f.rule == "L1-01/schema-violation"]
    assert len(schema) >= 1
    assert schema[0].severity == Severity.CRITICAL
