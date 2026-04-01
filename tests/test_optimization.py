"""Tests for optimization work: caching, dedup, progress, chaos improvements."""

from __future__ import annotations

import yaml

from xptest.chaos.engine import generate_perturbations
from xptest.loader import load
from xptest.logic.models import RenderedGraphSnapshot, RenderedResourceNode
from xptest.models import CompositionMode

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_snapshot(
    case_id: str = "test-0",
    resources: list[RenderedResourceNode] | None = None,
    edges: list[tuple[str, str]] | None = None,
    graph_hash: str = "abc123",
) -> RenderedGraphSnapshot:
    if resources is None:
        resources = [
            RenderedResourceNode(
                resource_id="db|DBCluster|aurora",
                role="aurora-db-cluster",
                api_version="rds.aws.crossplane.io/v1alpha1",
                kind="DBCluster",
                name="aurora",
                spec={"forProvider": {"region": "eu-central-1"}},
                identity_source="composition-resource-name",
            ),
            RenderedResourceNode(
                resource_id="db|DBSubnetGroup|subnet-group",
                role="db-subnet-group",
                api_version="database.aws.crossplane.io/v1beta1",
                kind="DBSubnetGroup",
                name="subnet-group",
                spec={"forProvider": {"subnetIds": ["subnet-1"]}},
                identity_source="composition-resource-name",
            ),
            RenderedResourceNode(
                resource_id="tde|XSecurityGroup|sg",
                role="security-group",
                api_version="tde.swisscom.com/v1alpha1",
                kind="XSecurityGroup",
                name="sg",
                spec={"groupName": "sg"},
                identity_source="composition-resource-name",
            ),
            RenderedResourceNode(
                resource_id="crossplane|XSecretKeeper|secret",
                role="aws-sm-master-user-credentials",
                api_version="crossplane.swisscom.com/v1alpha1",
                kind="XSecretKeeper",
                name="secret",
                spec={"resourceParameters": {"awsSecretName": "/crossplane/rds/test"}},
                identity_source="composition-resource-name",
            ),
        ]
    return RenderedGraphSnapshot(
        case_id=case_id,
        input_flat={"spec.engine": "aurora-postgresql"},
        resources=resources,
        edges=edges
        or [
            ("db|DBSubnetGroup|subnet-group", "db|DBCluster|aurora"),
            ("tde|XSecurityGroup|sg", "db|DBCluster|aurora"),
            ("crossplane|XSecretKeeper|secret", "db|DBCluster|aurora"),
        ],
        graph_hash=graph_hash,
    )


# ---------------------------------------------------------------------------
# Test: Pre-parsed doc passthrough in loader
# ---------------------------------------------------------------------------


class TestLoaderCaching:
    """Test that loader accepts pre-parsed docs to avoid re-reading YAML."""

    def test_load_with_preparsed_docs(self, tmp_path):
        """Passing _comp_doc and _xrd_doc should skip disk reads."""
        comp_doc = {
            "apiVersion": "apiextensions.crossplane.io/v1",
            "kind": "Composition",
            "metadata": {"name": "test"},
            "spec": {
                "compositeTypeRef": {"apiVersion": "test/v1", "kind": "XTest"},
                "mode": "Resources",
                "resources": [
                    {
                        "name": "vpc",
                        "base": {
                            "apiVersion": "ec2.aws.crossplane.io/v1beta1",
                            "kind": "VPC",
                            "spec": {},
                        },
                    }
                ],
            },
        }
        xrd_doc = {
            "apiVersion": "apiextensions.crossplane.io/v1",
            "kind": "CompositeResourceDefinition",
            "metadata": {"name": "xtest"},
            "spec": {
                "group": "test",
                "names": {"kind": "XTest"},
                "versions": [{"name": "v1"}],
            },
        }

        # Write files (needed for path validation in load)
        comp_path = str(tmp_path / "comp.yaml")
        xrd_path = str(tmp_path / "xrd.yaml")
        (tmp_path / "comp.yaml").write_text(yaml.dump(comp_doc))
        (tmp_path / "xrd.yaml").write_text(yaml.dump(xrd_doc))

        # Call load with pre-parsed docs
        obj = load(
            composition_path=comp_path,
            xrd_path=xrd_path,
            _comp_doc=comp_doc,
            _xrd_doc=xrd_doc,
        )
        assert obj.mode == CompositionMode.RESOURCES
        assert len(obj.resources) == 1
        assert obj.resources[0].kind == "VPC"

    def test_preparsed_docs_match_disk_load(self, tmp_path):
        """Verify that preparsed docs produce identical results to disk load."""
        comp_doc = {
            "apiVersion": "apiextensions.crossplane.io/v1",
            "kind": "Composition",
            "metadata": {"name": "test-consistency"},
            "spec": {
                "compositeTypeRef": {"apiVersion": "test/v1", "kind": "XTest"},
                "mode": "Resources",
                "resources": [
                    {
                        "name": "bucket",
                        "base": {
                            "apiVersion": "s3.aws.crossplane.io/v1beta1",
                            "kind": "Bucket",
                            "spec": {"forProvider": {"region": "us-east-1"}},
                        },
                    }
                ],
            },
        }
        xrd_doc = {
            "apiVersion": "apiextensions.crossplane.io/v1",
            "kind": "CompositeResourceDefinition",
            "metadata": {"name": "xtest"},
            "spec": {
                "group": "test",
                "names": {"kind": "XTest"},
                "versions": [{"name": "v1"}],
            },
        }
        comp_path = str(tmp_path / "comp.yaml")
        xrd_path = str(tmp_path / "xrd.yaml")
        (tmp_path / "comp.yaml").write_text(yaml.dump(comp_doc))
        (tmp_path / "xrd.yaml").write_text(yaml.dump(xrd_doc))

        obj_disk = load(composition_path=comp_path, xrd_path=xrd_path)
        obj_cache = load(
            composition_path=comp_path,
            xrd_path=xrd_path,
            _comp_doc=comp_doc,
            _xrd_doc=xrd_doc,
        )
        assert len(obj_disk.resources) == len(obj_cache.resources)
        assert obj_disk.resources[0].kind == obj_cache.resources[0].kind


# ---------------------------------------------------------------------------
# Test: Perturbation deduplication by graph_hash
# ---------------------------------------------------------------------------


class TestPerturbationDedup:
    """Test that identical graph_hash baselines are deduplicated."""

    def test_identical_hashes_produce_same_scenarios(self):
        """Two snapshots with same graph_hash should produce identical perturbations."""
        snap_a = _make_snapshot(case_id="combo-0", graph_hash="same-hash")
        snap_b = _make_snapshot(case_id="combo-1", graph_hash="same-hash")
        scenarios_a = generate_perturbations(snap_a, profile="both")
        scenarios_b = generate_perturbations(snap_b, profile="both")
        # Scenarios are structurally identical when graph is the same
        assert len(scenarios_a) == len(scenarios_b)
        for sa, sb in zip(scenarios_a, scenarios_b):
            assert sa.perturbation_id == sb.perturbation_id
            assert sa.kind == sb.kind

    def test_different_hashes_may_differ(self):
        """Different graph_hash means different perturbation set is allowed."""
        snap_a = _make_snapshot(case_id="combo-0", graph_hash="hash-a")
        snap_b = _make_snapshot(
            case_id="combo-1",
            graph_hash="hash-b",
            resources=[
                RenderedResourceNode(
                    resource_id="only-one",
                    role="only",
                    api_version="v1",
                    kind="ConfigMap",
                    name="only",
                    spec={},
                    identity_source="name",
                )
            ],
            edges=[],
        )
        scenarios_a = generate_perturbations(snap_a, profile="both")
        scenarios_b = generate_perturbations(snap_b, profile="both")
        # snap_b has no edges, fewer resources — different scenario count
        assert len(scenarios_a) != len(scenarios_b)


# ---------------------------------------------------------------------------
# Test: New chaos scenarios (R3-R6) are generated
# ---------------------------------------------------------------------------


class TestChaosScenarioQuality:
    """Test that new Crossplane-relevant chaos scenarios are generated."""

    def test_runtime_profile_generates_network_scenarios(self):
        scenarios = generate_perturbations(_make_snapshot(), profile="runtime")
        ids = {s.perturbation_id for s in scenarios}
        # Should have R3 for network resources (XSecurityGroup, DBSubnetGroup)
        assert "R3-network-dependency-absence" in ids

    def test_runtime_profile_generates_db_scenarios(self):
        scenarios = generate_perturbations(_make_snapshot(), profile="runtime")
        ids = {s.perturbation_id for s in scenarios}
        assert "R5-database-not-ready" in ids

    def test_runtime_profile_generates_hub_removal(self):
        """Hub dependency removal should target the highest fanout node."""
        scenarios = generate_perturbations(_make_snapshot(), profile="runtime")
        ids = {s.perturbation_id for s in scenarios}
        assert "R6-hub-dependency-removal" in ids

    def test_runtime_profile_generates_secret_scenarios(self):
        scenarios = generate_perturbations(_make_snapshot(), profile="runtime")
        ids = {s.perturbation_id for s in scenarios}
        assert "R1-external-secret-outage" in ids

    def test_both_profile_includes_all(self):
        """Profile 'both' should include synthetic + runtime scenarios."""
        scenarios = generate_perturbations(_make_snapshot(), profile="both")
        ids = {s.perturbation_id for s in scenarios}
        # Synthetic
        assert "P1-remove-first-resource" in ids
        # Runtime
        assert "R1-external-secret-outage" in ids
        assert "R3-network-dependency-absence" in ids

    def test_scenario_count_reasonable(self):
        """Check that scenario count is bounded and reasonable."""
        scenarios = generate_perturbations(_make_snapshot(), profile="both")
        # With 4 resources and 3 edges, should have P1-P4 + R1-R6 subset
        assert 5 <= len(scenarios) <= 15


# ---------------------------------------------------------------------------
# Test: Progress module
# ---------------------------------------------------------------------------


class TestProgressLogging:
    """Test that progress functions don't crash and produce output."""

    def test_init_and_elapsed(self):
        from xptest.progress import elapsed, init

        init()
        e = elapsed()
        assert e >= 0.0

    def test_phase_and_step(self, capsys):
        import io

        from xptest import progress

        progress._out = io.StringIO()
        progress.init()
        progress.phase("Test phase")
        progress.step("Test step")
        output = progress._out.getvalue()
        assert "Test phase" in output
        assert "Test step" in output
        # Restore
        progress._out = __import__("sys").stderr

    def test_combo_format(self):
        import io

        from xptest import progress

        progress._out = io.StringIO()
        progress.init()
        progress.combo(2, 10, "engine=aurora-mysql")
        output = progress._out.getvalue()
        assert "[3/10]" in output
        assert "engine=aurora-mysql" in output
        progress._out = __import__("sys").stderr
