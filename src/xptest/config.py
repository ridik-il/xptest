"""Load xptest.yaml config file."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Config:
    crd_bundle_path: str = ""
    opa_binary: str = "opa"
    severity_overrides: dict[str, str] = field(default_factory=dict)
    mandatory_tag_keys: list[str] = field(default_factory=list)


def load_config(config_path: str | None) -> Config:
    """Load config from xptest.yaml or return defaults."""
    if config_path is None:
        # Look for xptest.yaml in current working directory
        default_path = Path(os.getcwd()) / "xptest.yaml"
        if default_path.exists():
            config_path = str(default_path)
        else:
            return Config()

    with open(config_path) as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}

    return Config(
        crd_bundle_path=raw.get("crd_bundle_path", ""),
        opa_binary=raw.get("opa_binary", "opa"),
        severity_overrides=raw.get("severity_overrides", {}),
        mandatory_tag_keys=raw.get("mandatory_tag_keys", []),
    )
