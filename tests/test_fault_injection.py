"""Tests for fault injection protocol (Phase 5C)."""

from __future__ import annotations

from pathlib import Path

import yaml

from xptest.exploration.fault_injection import (
    build_fault_sweep_order,
    generate_fault_observed_resources,
)
from xptest.models import ComposedResource, CompositionMode, CompositionObject


def _resource(
    name: str,
    kind: str = "Bucket",
    patches: list | None = None,
) -> ComposedResource:
    return ComposedResource(
        name=name,
        api_version="s3.aws.upbound.io/v1beta1",
        kind=kind,
        spec={"forProvider": {"region": "us-east-1"}},
        patches=patches or [],
    )


def _obj(resources: list[ComposedResource]) -> CompositionObject:
    return CompositionObject(
        composition_name="test-comp",
        composition_path="/test/composition.yaml",
        xrd_name="xtest",
        xrd_path="/test/xrd.yaml",
        mode=CompositionMode.RESOURCES,
        resources=resources,
        xrd_spec={},
        crd_bundle_path="",
    )


def test_sweep_order_leaves_first():
    """Resources with no dependents (leaves) should come first."""
    # subnet depends on vpc via atProvider patch
    vpc = _resource("vpc", kind="VPC")
    subnet = _resource(
        "subnet",
        kind="Subnet",
        patches=[{
            "type": "FromCompositeFieldPath",
            "fromFieldPath": "status.atProvider.vpc.vpcId",
            "toFieldPath": "spec.forProvider.vpcId",
        }],
    )
    obj = _obj([vpc, subnet])
    order = build_fault_sweep_order(obj)

    # vpc is a producer; subnet is a consumer (leaf)
    # Leaves first in reverse topological order
    assert order.index("vpc") > order.index("subnet") or order == ["subnet", "vpc"]


def test_sweep_order_no_dependencies():
    """Resources with no patches have arbitrary order but all appear."""
    obj = _obj([_resource("a"), _resource("b"), _resource("c")])
    order = build_fault_sweep_order(obj)
    assert set(order) == {"a", "b", "c"}


def test_generate_fault_observed_resources():
    """Generates YAML with fault state for target, healthy for others."""
    obj = _obj([_resource("vpc", kind="VPC"), _resource("bucket")])
    path = generate_fault_observed_resources(obj, fault_target="vpc")

    try:
        with open(path) as fh:
            docs = list(yaml.safe_load_all(fh))

        assert len(docs) == 2

        # Find the faulted resource
        vpc_doc = next(d for d in docs if d["metadata"]["name"] == "vpc")
        assert vpc_doc["status"]["conditions"][0]["status"] == "False"
        assert vpc_doc["status"]["conditions"][0]["reason"] == "ReconcileError"
        assert vpc_doc["status"]["atProvider"] == {}

        # Find the healthy resource
        bucket_doc = next(d for d in docs if d["metadata"]["name"] == "bucket")
        assert bucket_doc["status"]["conditions"][0]["status"] == "True"
    finally:
        Path(path).unlink(missing_ok=True)


def test_fault_resource_has_annotation():
    """Fault resources should have composition-resource-name annotation."""
    obj = _obj([_resource("myresource")])
    path = generate_fault_observed_resources(obj, fault_target="myresource")
    try:
        with open(path) as fh:
            docs = list(yaml.safe_load_all(fh))
        ann = docs[0]["metadata"]["annotations"]
        assert ann["crossplane.io/composition-resource-name"] == "myresource"
    finally:
        Path(path).unlink(missing_ok=True)
