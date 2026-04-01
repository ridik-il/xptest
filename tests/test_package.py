"""Tests for package-level discovery."""

from __future__ import annotations

import yaml

from xptest.package import discover_package


def _write_composition(path, name, group, kind):
    doc = {
        "apiVersion": "apiextensions.crossplane.io/v1",
        "kind": "Composition",
        "metadata": {"name": name},
        "spec": {
            "compositeTypeRef": {
                "apiVersion": f"{group}/v1alpha1",
                "kind": kind,
            },
            "resources": [
                {
                    "name": "example",
                    "base": {
                        "apiVersion": "ec2.aws.upbound.io/v1beta1",
                        "kind": "VPC",
                        "spec": {},
                    },
                }
            ],
        },
    }
    path.write_text(yaml.dump(doc))


def _write_xrd(path, name, group, kind):
    doc = {
        "apiVersion": "apiextensions.crossplane.io/v1",
        "kind": "CompositeResourceDefinition",
        "metadata": {"name": name},
        "spec": {
            "group": group,
            "names": {"kind": kind},
            "versions": [
                {
                    "name": "v1alpha1",
                    "schema": {
                        "openAPIV3Schema": {
                            "properties": {
                                "spec": {
                                    "properties": {
                                        "region": {"type": "string"},
                                    }
                                }
                            }
                        }
                    },
                }
            ],
        },
    }
    path.write_text(yaml.dump(doc))


class TestDiscoverPackage:
    def test_discovers_matched_pair(self, tmp_path):
        _write_composition(tmp_path / "composition.yaml", "my-comp", "example.org", "XNetwork")
        _write_xrd(tmp_path / "xrd.yaml", "xnetworks.example.org", "example.org", "XNetwork")

        result = discover_package(str(tmp_path))
        assert len(result.entries) == 1
        assert result.entries[0].composition_name == "my-comp"
        assert result.entries[0].xrd_name == "xnetworks.example.org"
        assert not result.unmatched_compositions
        assert not result.unmatched_xrds

    def test_discovers_multiple_pairs(self, tmp_path):
        for name, group, kind in [
            ("net-comp", "net.example.org", "XNetwork"),
            ("db-comp", "db.example.org", "XDatabase"),
        ]:
            comp_dir = tmp_path / name
            comp_dir.mkdir()
            _write_composition(comp_dir / "composition.yaml", name, group, kind)
            _write_xrd(comp_dir / "xrd.yaml", f"{kind.lower()}s.{group}", group, kind)

        result = discover_package(str(tmp_path))
        assert len(result.entries) == 2

    def test_reports_unmatched_composition(self, tmp_path):
        _write_composition(tmp_path / "composition.yaml", "orphan", "missing.org", "XMissing")

        result = discover_package(str(tmp_path))
        assert len(result.entries) == 0
        assert len(result.unmatched_compositions) == 1

    def test_reports_unmatched_xrd(self, tmp_path):
        _write_xrd(tmp_path / "xrd.yaml", "xorphans.example.org", "example.org", "XOrphan")

        result = discover_package(str(tmp_path))
        assert len(result.entries) == 0
        assert len(result.unmatched_xrds) == 1

    def test_nonexistent_root(self):
        result = discover_package("/nonexistent/path")
        assert len(result.entries) == 0

    def test_nested_directory_discovery(self, tmp_path):
        nested = tmp_path / "apis" / "network"
        nested.mkdir(parents=True)
        _write_composition(
            nested / "composition.yaml", "nested-comp", "net.example.org", "XNetwork"
        )
        _write_xrd(nested / "xrd.yaml", "xnetworks.net.example.org", "net.example.org", "XNetwork")

        result = discover_package(str(tmp_path))
        assert len(result.entries) == 1

    def test_functions_yaml_auto_discovery(self, tmp_path):
        _write_composition(tmp_path / "composition.yaml", "comp", "example.org", "XTest")
        _write_xrd(tmp_path / "xrd.yaml", "xtests.example.org", "example.org", "XTest")
        # Write a functions.yaml
        func_doc = {
            "apiVersion": "pkg.crossplane.io/v1beta1",
            "kind": "Function",
            "metadata": {"name": "function-patch-and-transform"},
        }
        (tmp_path / "functions.yaml").write_text(yaml.dump(func_doc))

        result = discover_package(str(tmp_path))
        assert len(result.entries) == 1
        assert result.entries[0].functions_path == str(tmp_path / "functions.yaml")

    def test_explicit_functions_path_overrides(self, tmp_path):
        _write_composition(tmp_path / "composition.yaml", "comp", "example.org", "XTest")
        _write_xrd(tmp_path / "xrd.yaml", "xtests.example.org", "example.org", "XTest")

        result = discover_package(str(tmp_path), functions_path="/explicit/functions.yaml")
        assert result.entries[0].functions_path == "/explicit/functions.yaml"

    def test_scan_duration_recorded(self, tmp_path):
        _write_composition(tmp_path / "composition.yaml", "comp", "example.org", "XTest")
        _write_xrd(tmp_path / "xrd.yaml", "xtests.example.org", "example.org", "XTest")

        result = discover_package(str(tmp_path))
        assert result.scan_duration_s >= 0.0
