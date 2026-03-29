"""CRD bundle cache — load once, share across layers.

Avoids re-parsing the same CRD YAML files in Layer 1 (_build_crd_map,
_load_known_kinds) and Layer 2 (_load_atprovider_schemas). The cache
is built once per validation run and passed to each layer.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class CrdBundleCache:
    """Parsed CRD bundle data shared across L1 and L2."""

    __slots__ = (
        "known_kinds",
        "crd_schemas",
        "atprovider_schemas",
        "_bundle_path",
    )

    def __init__(
        self,
        known_kinds: set[tuple[str, str]],
        crd_schemas: dict[tuple[str, str], dict[str, Any]],
        atprovider_schemas: dict[tuple[str, str], dict[str, Any]],
        bundle_path: str,
    ) -> None:
        self.known_kinds = known_kinds
        self.crd_schemas = crd_schemas
        self.atprovider_schemas = atprovider_schemas
        self._bundle_path = bundle_path

    @property
    def bundle_path(self) -> str:
        return self._bundle_path


def load_crd_bundle(bundle_path: str) -> CrdBundleCache | None:
    """Parse all CRDs in a bundle directory and return a shared cache.

    Returns None if bundle_path is empty or not a directory.
    """
    if not bundle_path:
        return None
    bundle = Path(bundle_path)
    if not bundle.is_dir():
        return None

    known_kinds: set[tuple[str, str]] = set()
    crd_schemas: dict[tuple[str, str], dict[str, Any]] = {}
    atprovider_schemas: dict[tuple[str, str], dict[str, Any]] = {}

    for crd_file in bundle.rglob("*.yaml"):
        try:
            with crd_file.open() as fh:
                doc = yaml.safe_load(fh)
            if not isinstance(doc, dict) or doc.get("kind") != "CustomResourceDefinition":
                continue

            spec = doc.get("spec", {})
            group: str = spec.get("group", "")
            names: dict[str, Any] = spec.get("names", {})
            kind: str = names.get("kind", "")

            for v in spec.get("versions", []):
                v_name: str = v.get("name", "")
                if not (group and kind and v_name):
                    continue

                api_version = f"{group}/{v_name}"
                key = (api_version, kind)
                known_kinds.add(key)

                # openAPIV3Schema for L1 schema validation
                schema_block = v.get("schema", {}).get("openAPIV3Schema", {})
                if schema_block:
                    crd_schemas[key] = schema_block

                # atProvider field names for L2 reference completeness
                at_provider_props = (
                    schema_block.get("properties", {})
                    .get("status", {})
                    .get("properties", {})
                    .get("atProvider", {})
                    .get("properties", {})
                )
                if at_provider_props:
                    atprovider_schemas[key] = at_provider_props

        except Exception:  # noqa: BLE001
            continue

    return CrdBundleCache(
        known_kinds=known_kinds,
        crd_schemas=crd_schemas,
        atprovider_schemas=atprovider_schemas,
        bundle_path=bundle_path,
    )
