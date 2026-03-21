"""Tests for config loading and validation."""

from __future__ import annotations

import pytest

from xptest.config import ConfigError, load_config


def test_defaults_when_no_config_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = load_config(None)
    assert cfg.crd_bundle_path == ""
    assert cfg.rules_path == ""
    assert cfg.opa_binary == "opa"
    assert cfg.opa_expected_version == ""
    assert cfg.environment_config_paths == []
    assert cfg.severity_overrides == {}
    assert cfg.mandatory_tag_keys == []


def test_load_full_config(tmp_path):
    cfg_file = tmp_path / "xptest.yaml"
    cfg_file.write_text(
        """\
crd_bundle_path: ./schemas/provider-v1
rules_path: ./rules/aws
opa_binary: /usr/local/bin/opa
opa_expected_version: "0.68.0"
environment_config_paths:
  - ./envconfig1.yaml
  - ./envconfig2.yaml
severity_overrides:
  tag/mandatory-keys: CRITICAL
  net/sg-no-open-ssh: WARNING
mandatory_tag_keys:
  - Environment
  - Owner
"""
    )

    cfg = load_config(str(cfg_file))
    assert cfg.crd_bundle_path == str((tmp_path / "schemas" / "provider-v1").resolve())
    assert cfg.rules_path == str((tmp_path / "rules" / "aws").resolve())
    assert cfg.opa_binary == "/usr/local/bin/opa"
    assert cfg.opa_expected_version == "0.68.0"
    assert len(cfg.environment_config_paths) == 2
    assert cfg.severity_overrides == {
        "tag/mandatory-keys": "CRITICAL",
        "net/sg-no-open-ssh": "WARNING",
    }
    assert cfg.mandatory_tag_keys == ["Environment", "Owner"]


def test_relative_paths_resolved_from_config_dir(tmp_path):
    sub = tmp_path / "project"
    sub.mkdir()
    cfg_file = sub / "xptest.yaml"
    cfg_file.write_text("crd_bundle_path: ../schemas\nrules_path: ./rules\n")

    cfg = load_config(str(cfg_file))
    assert cfg.crd_bundle_path == str((tmp_path / "schemas").resolve())
    assert cfg.rules_path == str((sub / "rules").resolve())


def test_absolute_paths_unchanged(tmp_path):
    cfg_file = tmp_path / "xptest.yaml"
    cfg_file.write_text("crd_bundle_path: /opt/crds\n")

    cfg = load_config(str(cfg_file))
    assert cfg.crd_bundle_path == "/opt/crds"


def test_invalid_severity_raises(tmp_path):
    cfg_file = tmp_path / "xptest.yaml"
    cfg_file.write_text("severity_overrides:\n  some/rule: FATAL\n")

    with pytest.raises(ConfigError, match="Invalid severity 'FATAL'"):
        load_config(str(cfg_file))


def test_missing_config_file_raises():
    with pytest.raises(ConfigError, match="Config file not found"):
        load_config("/nonexistent/xptest.yaml")


def test_auto_discover_in_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg_file = tmp_path / "xptest.yaml"
    cfg_file.write_text("mandatory_tag_keys:\n  - Team\n")

    cfg = load_config(None)
    assert cfg.mandatory_tag_keys == ["Team"]
