"""Tests for CRD bundle cache."""

from __future__ import annotations

import yaml

from xptest.cache import CrdBundleCache, load_crd_bundle


class TestLoadCrdBundle:
    def test_returns_none_for_empty_path(self):
        assert load_crd_bundle("") is None

    def test_returns_none_for_nonexistent_dir(self):
        assert load_crd_bundle("/nonexistent/path") is None

    def test_loads_known_kinds(self, tmp_path):
        crd = {
            "kind": "CustomResourceDefinition",
            "spec": {
                "group": "ec2.aws.upbound.io",
                "names": {"kind": "VPC"},
                "versions": [
                    {
                        "name": "v1beta1",
                        "schema": {
                            "openAPIV3Schema": {
                                "properties": {
                                    "spec": {"type": "object"},
                                    "status": {
                                        "properties": {
                                            "atProvider": {
                                                "properties": {
                                                    "id": {"type": "string"},
                                                    "arn": {"type": "string"},
                                                }
                                            }
                                        }
                                    },
                                }
                            }
                        },
                    }
                ],
            },
        }
        (tmp_path / "vpc.yaml").write_text(yaml.dump(crd))

        cache = load_crd_bundle(str(tmp_path))
        assert cache is not None
        assert ("ec2.aws.upbound.io/v1beta1", "VPC") in cache.known_kinds
        assert ("ec2.aws.upbound.io/v1beta1", "VPC") in cache.crd_schemas
        assert ("ec2.aws.upbound.io/v1beta1", "VPC") in cache.atprovider_schemas
        assert cache.atprovider_schemas[("ec2.aws.upbound.io/v1beta1", "VPC")] == {
            "id", "arn"
        }

    def test_loads_multiple_crds(self, tmp_path):
        for kind_name, group in [("VPC", "ec2.aws.upbound.io"), ("Bucket", "s3.aws.upbound.io")]:
            crd = {
                "kind": "CustomResourceDefinition",
                "spec": {
                    "group": group,
                    "names": {"kind": kind_name},
                    "versions": [
                        {
                            "name": "v1beta1",
                            "schema": {
                                "openAPIV3Schema": {
                                    "properties": {"spec": {"type": "object"}}
                                }
                            },
                        }
                    ],
                },
            }
            (tmp_path / f"{kind_name.lower()}.yaml").write_text(yaml.dump(crd))

        cache = load_crd_bundle(str(tmp_path))
        assert cache is not None
        assert len(cache.known_kinds) == 2

    def test_skips_non_crd_files(self, tmp_path):
        (tmp_path / "not-a-crd.yaml").write_text(yaml.dump({"kind": "ConfigMap"}))
        cache = load_crd_bundle(str(tmp_path))
        assert cache is not None
        assert len(cache.known_kinds) == 0

    def test_cache_is_shared_reference(self, tmp_path):
        crd = {
            "kind": "CustomResourceDefinition",
            "spec": {
                "group": "ec2.aws.upbound.io",
                "names": {"kind": "VPC"},
                "versions": [
                    {
                        "name": "v1beta1",
                        "schema": {
                            "openAPIV3Schema": {
                                "properties": {"spec": {"type": "object"}}
                            }
                        },
                    }
                ],
            },
        }
        (tmp_path / "vpc.yaml").write_text(yaml.dump(crd))

        cache = load_crd_bundle(str(tmp_path))
        assert isinstance(cache, CrdBundleCache)
        assert cache.bundle_path == str(tmp_path)
