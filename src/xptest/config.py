"""Load xptest.yaml config file.

Schema:
    crd_bundle_path:          str   — directory containing CRD YAML files
    rules_path:               str   — directory containing OPA Rego rule files
    opa_binary:               str   — OPA binary path or command name
    opa_expected_version:     str   — pinned OPA version for reproducibility (NF6)
    environment_config_paths: list  — EnvironmentConfig fixture YAML paths
    severity_overrides:       dict  — rule-id → severity (CRITICAL/WARNING/INFO)
    mandatory_tag_keys:       list  — required tag keys for tag/mandatory-keys rule

Relative paths are resolved relative to the config file's parent directory,
not the current working directory.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_VALID_SEVERITIES = {"CRITICAL", "WARNING", "INFO"}


@dataclass
class Config:
    crd_bundle_path: str = ""
    rules_path: str = ""
    opa_binary: str = "opa"
    opa_expected_version: str = ""
    environment_config_paths: list[str] = field(default_factory=list)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    mandatory_tag_keys: list[str] = field(default_factory=list)


class ConfigError(ValueError):
    pass


def load_config(config_path: str | None) -> Config:
    """Load config from xptest.yaml or return defaults.

    If *config_path* is None, looks for ``xptest.yaml`` in the current working
    directory.  If no config file is found, returns a Config with all defaults.
    """
    if config_path is None:
        default_path = Path(os.getcwd()) / "xptest.yaml"
        if default_path.exists():
            config_path = str(default_path)
        else:
            return Config()

    config_file = Path(config_path)
    if not config_file.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    base_dir = config_file.parent

    with config_file.open() as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}

    severity_overrides = raw.get("severity_overrides", {})
    _validate_severity_overrides(severity_overrides)

    return Config(
        crd_bundle_path=_resolve_path(raw.get("crd_bundle_path", ""), base_dir),
        rules_path=_resolve_path(raw.get("rules_path", ""), base_dir),
        opa_binary=raw.get("opa_binary", "opa"),
        opa_expected_version=str(raw.get("opa_expected_version", "")),
        environment_config_paths=[
            _resolve_path(p, base_dir) for p in raw.get("environment_config_paths", [])
        ],
        severity_overrides=severity_overrides,
        mandatory_tag_keys=raw.get("mandatory_tag_keys", []),
    )


def _resolve_path(value: str, base_dir: Path) -> str:
    """Resolve a potentially relative path against the config file's directory."""
    if not value:
        return ""
    p = Path(value)
    if p.is_absolute():
        return str(p)
    return str((base_dir / p).resolve())


def _validate_severity_overrides(overrides: dict[str, Any]) -> None:
    """Raise ConfigError if any severity override value is not a valid severity."""
    if not isinstance(overrides, dict):
        raise ConfigError("severity_overrides must be a mapping of rule-id → severity")
    for rule_id, severity in overrides.items():
        if not isinstance(severity, str) or severity.upper() not in _VALID_SEVERITIES:
            raise ConfigError(
                f"Invalid severity '{severity}' for rule '{rule_id}'. "
                f"Must be one of: {', '.join(sorted(_VALID_SEVERITIES))}"
            )
