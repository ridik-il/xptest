"""Tests for layer5_rules.py functions and cli.py oneOf/discovery helpers."""

from __future__ import annotations

from xptest.cli import (
    _combo_satisfies_oneof,
    _discover_base_xrs,
    _extract_oneof_constraints,
)
from xptest.layer5_rules import (
    check_cross_composition,
    check_deletion_policy,
    check_env_matrix,
    check_sg_reachability,
    check_tag_propagation,
)
from xptest.models import Severity

# ---------------------------------------------------------------------------
# oneOf constraints (cli.py)
# ---------------------------------------------------------------------------

_ONEOF_SCHEMA = {
    "properties": {
        "loadBalancerType": {"type": "string"},
        "protocol": {"type": "string"},
    },
    "oneOf": [
        {
            "properties": {
                "loadBalancerType": {"enum": ["application"]},
                "protocol": {"enum": ["HTTP", "HTTPS"]},
            }
        },
        {
            "properties": {
                "loadBalancerType": {"enum": ["network"]},
                "protocol": {"enum": ["TCP", "UDP"]},
            }
        },
    ],
}


def test_extract_oneof_constraints_basic():
    constraints = _extract_oneof_constraints(_ONEOF_SCHEMA)
    assert len(constraints) == 2
    assert "loadBalancerType" in constraints[0]


def test_extract_oneof_constraints_empty():
    assert _extract_oneof_constraints({"properties": {"x": {"type": "string"}}}) == []


def test_combo_satisfies_oneof_valid():
    constraints = _extract_oneof_constraints(_ONEOF_SCHEMA)
    assert _combo_satisfies_oneof({"loadBalancerType": "application"}, constraints)


def test_combo_satisfies_oneof_invalid():
    constraints = _extract_oneof_constraints(_ONEOF_SCHEMA)
    assert not _combo_satisfies_oneof(
        {"loadBalancerType": "network", "protocol": "HTTP"}, constraints
    )


def test_combo_satisfies_oneof_no_constraints():
    assert _combo_satisfies_oneof({"anything": "goes"}, [])


# ---------------------------------------------------------------------------
# discover_base_xrs (cli.py)
# ---------------------------------------------------------------------------


def test_discover_base_xrs_finds_files(tmp_path):
    comp = tmp_path / "pkg" / "community" / "ec2" / "composition.yaml"
    comp.parent.mkdir(parents=True)
    comp.write_text("kind: Composition")
    res_dir = tmp_path / "composition-tests" / "community" / "ec2" / "resources"
    res_dir.mkdir(parents=True)
    (res_dir / "xr-min.yaml").write_text("kind: XR")
    found = _discover_base_xrs(str(comp))
    assert len(found) == 1
    assert "xr-min.yaml" in found[0]


def test_discover_base_xrs_skips_bad(tmp_path):
    comp = tmp_path / "pkg" / "svc" / "composition.yaml"
    comp.parent.mkdir(parents=True)
    comp.write_text("")
    res_dir = tmp_path / "composition-tests" / "svc" / "resources"
    res_dir.mkdir(parents=True)
    (res_dir / "xr-bad-params.yaml").write_text("")
    (res_dir / "xr-good.yaml").write_text("")
    found = _discover_base_xrs(str(comp))
    assert all("bad" not in f for f in found)
    assert len(found) == 1


def test_discover_base_xrs_no_pkg(tmp_path):
    comp = tmp_path / "other" / "composition.yaml"
    comp.parent.mkdir(parents=True)
    comp.write_text("")
    assert _discover_base_xrs(str(comp)) == []


# ---------------------------------------------------------------------------
# check_sg_reachability (layer5_rules.py)
# ---------------------------------------------------------------------------


def _sg_resource(cidrs: list[str], *, add_default: bool = False) -> dict:
    ingress = [{"cidrBlocks": cidrs}]
    if add_default:
        ingress[0]["addDefaultIPRanges"] = True
    return {
        "kind": "SecurityGroup",
        "metadata": {"name": "sg", "annotations": {}},
        "spec": {"forProvider": {"ingress": ingress}},
    }


def test_sg_reachability_all_covered():
    env = {"vpcSubnetPrivateNonRoutableCidr1": "10.0.0.0/24"}
    findings = check_sg_reachability([_sg_resource(["10.0.0.0/16"])], env)
    assert len(findings) == 0


def test_sg_reachability_missing_cidr():
    env = {"vpcSubnetPrivateNonRoutableCidr1": "10.0.0.0/24"}
    findings = check_sg_reachability([_sg_resource(["192.168.0.0/16"])], env)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_sg_reachability_with_default_ip_ranges():
    env = {"vpcSubnetPrivateNonRoutableCidr1": "10.0.0.0/24"}
    findings = check_sg_reachability([_sg_resource(["192.168.0.0/16"], add_default=True)], env)
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING


def test_sg_reachability_no_sg():
    env = {"vpcSubnetPrivateNonRoutableCidr1": "10.0.0.0/24"}
    assert check_sg_reachability([{"kind": "Bucket", "spec": {}}], env) == []


# ---------------------------------------------------------------------------
# check_deletion_policy (layer5_rules.py)
# ---------------------------------------------------------------------------


def _res(policy: str) -> dict:
    return {
        "kind": "Bucket",
        "metadata": {"name": "b", "annotations": {}},
        "spec": {"deletionPolicy": policy},
    }


def _xr(policy: str) -> dict:
    return {"spec": {"crossplaneParameters": {"deletionPolicy": policy}}}


def test_deletion_policy_consistent():
    assert check_deletion_policy([_res("Orphan")], _xr("Orphan")) == []


def test_deletion_policy_mismatch():
    findings = check_deletion_policy([_res("Delete")], _xr("Orphan"))
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING


def test_deletion_policy_no_xr_policy():
    assert check_deletion_policy([_res("Delete")], {"spec": {}}) == []


# ---------------------------------------------------------------------------
# check_tag_propagation (layer5_rules.py)
# ---------------------------------------------------------------------------


def _tagged_res(tags: dict) -> dict:
    return {
        "kind": "Bucket",
        "metadata": {"name": "b", "annotations": {}},
        "spec": {"forProvider": {"tags": tags}},
    }


def test_tags_all_present():
    assert (
        check_tag_propagation(
            [_tagged_res({"claim-name": "x", "created-by": "y"})],
        )
        == []
    )


def test_tags_missing():
    findings = check_tag_propagation([_tagged_res({"claim-name": "x"})])
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING
    assert "created-by" in findings[0].message


def test_tags_exempt_kind():
    res = _tagged_res({})
    res["kind"] = "DBClusterParameterGroup"
    assert check_tag_propagation([res], exempt_kinds=["DBClusterParameterGroup"]) == []


def test_tags_no_forprovider():
    res = {"kind": "Bucket", "metadata": {"name": "b", "annotations": {}}, "spec": {}}
    assert check_tag_propagation([res]) == []


# ---------------------------------------------------------------------------
# check_cross_composition (layer5_rules.py)
# ---------------------------------------------------------------------------


def _pcr_res(name: str) -> dict:
    return {
        "kind": "Bucket",
        "metadata": {"name": "b", "annotations": {}},
        "spec": {"providerConfigRef": {"name": name}},
    }


_ENV_DATA = {
    "crossplane": {
        "providers": {
            "aws": {"configRef": "providerconfig-aws"},
        }
    }
}


def test_cross_comp_known_config():
    assert check_cross_composition([_pcr_res("providerconfig-aws")], _ENV_DATA) == []


def test_cross_comp_unknown_config():
    findings = check_cross_composition([_pcr_res("providerconfig-gcp")], _ENV_DATA)
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING


def test_cross_comp_pattern_match():
    findings = check_cross_composition(
        [_pcr_res("providerconfig-aws-demo")],
        _ENV_DATA,
        known_patterns=["providerconfig-aws*"],
    )
    assert findings == []


# ---------------------------------------------------------------------------
# check_env_matrix (layer5_rules.py) — unit-safe boundary test
# ---------------------------------------------------------------------------


def test_env_matrix_single_envconfig():
    assert check_env_matrix("comp.yaml", "xrd.yaml", "fn.yaml", {}, ["one.yaml"]) == []
