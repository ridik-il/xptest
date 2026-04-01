"""Tests for Layer 3 — Policy Compliance (OPA Rego).

Tests are split into:
  - Unit tests for _build_input and _violations_to_findings (no OPA needed).
  - Integration tests that call OPA (skipped if OPA is not on PATH).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from xptest.config import Config
from xptest.layer3 import policy as layer3
from xptest.loader import load
from xptest.models import Finding, Severity

_HERE = Path(__file__).parent
FIXTURES_DIR = _HERE.parent / "fixtures"
RULES_DIR = _HERE.parent / "rules" / "aws"
XRD_PATH = str(FIXTURES_DIR / "xrd.yaml")

HAS_OPA = shutil.which("opa") is not None


def _load_fixture(name: str):
    return load(str(FIXTURES_DIR / "policy-violations" / name), XRD_PATH)


def _config(**overrides) -> Config:
    defaults = {
        "rules_path": str(RULES_DIR),
        "opa_binary": "opa",
        "mandatory_tag_keys": [],
    }
    defaults.update(overrides)
    return Config(**defaults)


# ────────────────────────────────────────────────────────
# Unit tests: _build_input
# ────────────────────────────────────────────────────────


class TestBuildInput:
    def test_resources_included(self):
        obj = _load_fixture("rds-unencrypted-public.yaml")
        cfg = _config(mandatory_tag_keys=["Environment"])
        result = layer3._build_input(obj, cfg)

        assert "resources" in result
        assert len(result["resources"]) == 1
        assert result["resources"][0]["name"] == "bad-db"
        assert result["resources"][0]["kind"] == "DBInstance"

    def test_config_section(self):
        obj = _load_fixture("rds-unencrypted-public.yaml")
        cfg = _config(mandatory_tag_keys=["Environment", "Owner"])
        result = layer3._build_input(obj, cfg)

        assert result["config"]["mandatory_tag_keys"] == ["Environment", "Owner"]

    def test_multiple_resources(self):
        obj = _load_fixture("cross-resource-rds.yaml")
        cfg = _config()
        result = layer3._build_input(obj, cfg)

        names = {r["name"] for r in result["resources"]}
        assert names == {"db-role", "db-sg", "main-db"}


# ────────────────────────────────────────────────────────
# Unit tests: _violations_to_findings
# ────────────────────────────────────────────────────────


class TestViolationsToFindings:
    def test_basic_conversion(self):
        violations = [
            {
                "rule": "enc/rds-encrypted",
                "resource": "bad-db",
                "path": "spec.forProvider.storageEncrypted",
                "severity": "CRITICAL",
                "message": "RDS not encrypted.",
                "remediation": "Set storageEncrypted: true.",
            }
        ]
        cfg = _config()
        findings = layer3._violations_to_findings(violations, cfg)

        assert len(findings) == 1
        assert findings[0].layer == 3
        assert findings[0].rule == "enc/rds-encrypted"
        assert findings[0].severity == Severity.CRITICAL

    def test_severity_override(self):
        violations = [
            {
                "rule": "tag/mandatory-keys",
                "severity": "WARNING",
                "resource": "vpc",
                "path": "",
                "message": "",
                "remediation": "",
            }
        ]
        cfg = _config(severity_overrides={"tag/mandatory-keys": "CRITICAL"})
        findings = layer3._violations_to_findings(violations, cfg)

        assert findings[0].severity == Severity.CRITICAL

    def test_missing_severity_defaults_to_critical(self):
        violations = [{"rule": "unknown/rule"}]
        cfg = _config()
        findings = layer3._violations_to_findings(violations, cfg)

        assert findings[0].severity == Severity.CRITICAL

    def test_empty_violations(self):
        findings = layer3._violations_to_findings([], _config())
        assert findings == []


# ────────────────────────────────────────────────────────
# Unit tests: run() with no rules_path
# ────────────────────────────────────────────────────────


class TestRunWithoutOpa:
    def test_no_rules_path_returns_empty(self):
        obj = _load_fixture("rds-unencrypted-public.yaml")
        cfg = _config(rules_path="")
        assert layer3.run(obj, cfg) == []

    def test_nonexistent_rules_path_returns_empty(self):
        obj = _load_fixture("rds-unencrypted-public.yaml")
        cfg = _config(rules_path="/nonexistent/path")
        assert layer3.run(obj, cfg) == []


# ────────────────────────────────────────────────────────
# Unit tests: run() with mocked OPA subprocess
# ────────────────────────────────────────────────────────


class TestRunMocked:
    def _mock_opa_result(self, violations: list[dict]):
        """Build the JSON structure OPA eval returns."""
        return json.dumps({"result": [{"expressions": [{"value": violations}]}]})

    @patch("xptest.layer3.policy._run_opa_query")
    def test_rds_encryption_violation(self, mock_query):
        mock_query.return_value = [
            {
                "rule": "enc/rds-encrypted",
                "resource": "bad-db",
                "path": "spec.forProvider.storageEncrypted",
                "severity": "CRITICAL",
                "message": "RDS not encrypted.",
                "remediation": "Set storageEncrypted: true.",
            }
        ]

        obj = _load_fixture("rds-unencrypted-public.yaml")
        cfg = _config()
        findings = layer3.run(obj, cfg)

        enc_findings = [f for f in findings if f.rule == "enc/rds-encrypted"]
        assert len(enc_findings) >= 1
        assert enc_findings[0].severity == Severity.CRITICAL

    @patch("xptest.layer3.policy._run_opa_query")
    def test_opa_file_not_found_raises(self, mock_query):
        mock_query.side_effect = layer3.OpaError("OPA binary 'opa' not found.")

        obj = _load_fixture("rds-unencrypted-public.yaml")
        cfg = _config()
        with pytest.raises(layer3.OpaError, match="not found"):
            layer3.run(obj, cfg)


# ────────────────────────────────────────────────────────
# Integration tests: real OPA binary (skipped if not installed)
# ────────────────────────────────────────────────────────


@pytest.mark.skipif(not HAS_OPA, reason="OPA binary not found on PATH")
class TestOpaIntegration:
    def _run_policy(self, fixture_name: str, **cfg_overrides) -> list[Finding]:
        obj = _load_fixture(fixture_name)
        cfg = _config(**cfg_overrides)
        return layer3.run(obj, cfg)

    def _load_expected(self, fixture_name: str) -> list[dict]:
        stem = fixture_name.replace(".yaml", "")
        path = FIXTURES_DIR / "policy-violations" / f"{stem}-expected.json"
        return json.loads(path.read_text())

    def _assert_expected_rules(self, findings: list[Finding], expected: list[dict]):
        found_rules = {f.rule for f in findings}
        for exp in expected:
            assert exp["rule"] in found_rules, (
                f"Expected rule {exp['rule']} not found in {found_rules}"
            )

    def test_rds_unencrypted_public(self):
        findings = self._run_policy("rds-unencrypted-public.yaml")
        expected = self._load_expected("rds-unencrypted-public.yaml")
        self._assert_expected_rules(findings, expected)

    def test_sg_open_ssh_db(self):
        findings = self._run_policy("sg-open-ssh-db.yaml")
        expected = self._load_expected("sg-open-ssh-db.yaml")
        self._assert_expected_rules(findings, expected)

    def test_iam_wildcard(self):
        findings = self._run_policy("iam-wildcard.yaml")
        expected = self._load_expected("iam-wildcard.yaml")
        self._assert_expected_rules(findings, expected)

    def test_cross_resource_rds(self):
        findings = self._run_policy("cross-resource-rds.yaml")
        expected = self._load_expected("cross-resource-rds.yaml")
        self._assert_expected_rules(findings, expected)

    def test_s3_no_encryption(self):
        findings = self._run_policy("s3-no-encryption.yaml")
        expected = self._load_expected("s3-no-encryption.yaml")
        self._assert_expected_rules(findings, expected)

    def test_tagging_missing(self):
        findings = self._run_policy(
            "tagging-missing.yaml",
            mandatory_tag_keys=["Environment", "Owner"],
        )
        expected = self._load_expected("tagging-missing.yaml")
        self._assert_expected_rules(findings, expected)

    def test_valid_composition_no_policy_findings(self):
        obj = load(str(FIXTURES_DIR / "valid" / "vpc-subnet-iam.yaml"), XRD_PATH)
        cfg = _config()
        findings = layer3.run(obj, cfg)
        # Valid composition should have no policy violations
        # (encryption/network rules only fire on specific resource types)
        l3_findings = [f for f in findings if f.layer == 3]
        # The valid fixture has VPC, Subnet, Role — none should trigger policy rules
        assert l3_findings == [], f"Unexpected findings: {l3_findings}"
