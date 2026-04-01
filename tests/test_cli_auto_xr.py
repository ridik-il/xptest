from __future__ import annotations

from pathlib import Path

import yaml

from xptest.cli import _field_options, _generate_auto_xr_candidates


def _write_xrd(tmp_path: Path, kind: str, spec_properties: dict) -> str:
    xrd = {
        "apiVersion": "apiextensions.crossplane.io/v1",
        "kind": "CompositeResourceDefinition",
        "metadata": {"name": f"{kind.lower()}s.example.org"},
        "spec": {
            "group": "example.org",
            "names": {"kind": kind, "plural": f"{kind.lower()}s"},
            "versions": [
                {
                    "name": "v1alpha1",
                    "served": True,
                    "referenceable": True,
                    "schema": {
                        "openAPIV3Schema": {
                            "type": "object",
                            "properties": {
                                "spec": {
                                    "type": "object",
                                    "properties": spec_properties,
                                    "required": list(spec_properties.keys()),
                                }
                            },
                        }
                    },
                }
            ],
        },
    }

    path = tmp_path / "definition.yaml"
    path.write_text(yaml.safe_dump(xrd, sort_keys=False))
    return str(path)


def test_field_options_namespace_generates_dev_prod():
    opts = _field_options("serviceAccountNamespace", {"type": "string"})
    assert opts == ["dev", "prod"]


def test_generate_auto_xr_candidates_from_service_account_xrd(tmp_path):
    xrd_path = _write_xrd(
        tmp_path,
        kind="XSrvAccount",
        spec_properties={"serviceAccountNamespace": {"type": "string"}},
    )
    candidates = _generate_auto_xr_candidates(xrd_path, max_count=4)

    assert len(candidates) >= 2
    kinds = {doc["kind"] for _label, doc in candidates}
    assert kinds == {"XSrvAccount"}

    namespaces = {doc["spec"].get("serviceAccountNamespace") for _label, doc in candidates}
    assert "dev" in namespaces
    assert "prod" in namespaces


def test_generate_auto_xr_candidates_from_nested_rds_xrd(tmp_path):
    xrd_path = _write_xrd(
        tmp_path,
        kind="XAurora",
        spec_properties={
            "crossplaneParameters": {
                "type": "object",
                "properties": {
                    "deletionPolicy": {
                        "type": "string",
                        "enum": ["Orphan", "Delete"],
                    }
                },
                "required": ["deletionPolicy"],
            }
        },
    )
    candidates = _generate_auto_xr_candidates(xrd_path, max_count=10)

    assert len(candidates) >= 2
    deletion_policies = {
        doc["spec"].get("crossplaneParameters", {}).get("deletionPolicy")
        for _label, doc in candidates
    }
    assert "Orphan" in deletion_policies
    assert "Delete" in deletion_policies
