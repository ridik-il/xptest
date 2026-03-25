from __future__ import annotations

from xptest.cli import _field_options, _generate_auto_xr_candidates


def test_field_options_namespace_generates_dev_prod():
    opts = _field_options("serviceAccountNamespace", {"type": "string"})
    assert opts == ["dev", "prod"]


def test_generate_auto_xr_candidates_from_service_account_xrd():
    xrd_path = (
        "../crossplane-composition-tester/test/pkg/service-account-with-functions/definition.yaml"
    )
    candidates = _generate_auto_xr_candidates(xrd_path, max_count=4)

    assert len(candidates) >= 2
    kinds = {doc["kind"] for _label, doc in candidates}
    assert kinds == {"XSrvAccount"}

    namespaces = {doc["spec"].get("serviceAccountNamespace") for _label, doc in candidates}
    assert "dev" in namespaces
    assert "prod" in namespaces


def test_generate_auto_xr_candidates_from_nested_rds_xrd():
    xrd_path = "../xplane-pkg/pkg/rds-aurora/definition.yaml"
    candidates = _generate_auto_xr_candidates(xrd_path, max_count=10)

    assert len(candidates) >= 2
    deletion_policies = {
        doc["spec"].get("crossplaneParameters", {}).get("deletionPolicy")
        for _label, doc in candidates
    }
    assert "Orphan" in deletion_policies
    assert "Delete" in deletion_policies
