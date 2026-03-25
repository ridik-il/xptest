"""Package-level scanning — discover all Compositions and XRDs under a root.

Recursively walks a directory tree, identifies Crossplane YAML files by their
``kind`` field, and matches each Composition to its XRD via
``spec.compositeTypeRef``.  Also discovers functions.yaml files for Pipeline
mode compositions.

Usage:
    entries = discover_package("/path/to/package")
    for entry in entries:
        obj = load(entry.composition_path, entry.xrd_path, ...)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class PackageEntry:
    """A matched Composition + XRD pair discovered in a package."""

    composition_path: str
    composition_name: str
    xrd_path: str
    xrd_name: str
    functions_path: str | None = None
    environment_config_paths: list[str] = field(default_factory=list)


@dataclass
class PackageScanResult:
    """Result of scanning a package directory."""

    entries: list[PackageEntry]
    unmatched_compositions: list[str]
    unmatched_xrds: list[str]
    scan_duration_s: float = 0.0


def discover_package(
    root: str,
    functions_path: str | None = None,
    environment_config_paths: list[str] | None = None,
) -> PackageScanResult:
    """Recursively discover Compositions and XRDs under root.

    Matches each Composition to its XRD using spec.compositeTypeRef.group
    and spec.compositeTypeRef.kind against XRD spec.group + spec.names.kind.

    Args:
        root: Directory to scan recursively.
        functions_path: Optional functions.yaml override for all compositions.
        environment_config_paths: Optional env config files for all compositions.

    Returns:
        PackageScanResult with matched entries and unmatched files.
    """
    start = time.monotonic()
    root_path = Path(root)
    if not root_path.is_dir():
        return PackageScanResult(
            entries=[],
            unmatched_compositions=[],
            unmatched_xrds=[],
            scan_duration_s=0.0,
        )

    compositions: list[tuple[str, dict[str, Any]]] = []
    xrds: list[tuple[str, dict[str, Any]]] = []
    discovered_functions: list[str] = []

    # Scan all YAML files
    for yaml_file in sorted(root_path.rglob("*.yaml")):
        try:
            with yaml_file.open() as fh:
                doc = yaml.safe_load(fh)
            if not isinstance(doc, dict):
                continue

            kind = doc.get("kind", "")
            if kind == "Composition":
                compositions.append((str(yaml_file), doc))
            elif kind == "CompositeResourceDefinition":
                xrds.append((str(yaml_file), doc))
            elif kind == "Function":
                discovered_functions.append(str(yaml_file))
        except Exception:  # noqa: BLE001
            continue

    # Also scan .yml files
    for yaml_file in sorted(root_path.rglob("*.yml")):
        try:
            with yaml_file.open() as fh:
                doc = yaml.safe_load(fh)
            if not isinstance(doc, dict):
                continue

            kind = doc.get("kind", "")
            if kind == "Composition":
                compositions.append((str(yaml_file), doc))
            elif kind == "CompositeResourceDefinition":
                xrds.append((str(yaml_file), doc))
            elif kind == "Function":
                discovered_functions.append(str(yaml_file))
        except Exception:  # noqa: BLE001
            continue

    # Build XRD index: (group, kind) -> (path, doc)
    xrd_index: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
    for xrd_path, xrd_doc in xrds:
        xrd_spec = xrd_doc.get("spec", {})
        group = xrd_spec.get("group", "")
        kind = xrd_spec.get("names", {}).get("kind", "")
        if group and kind:
            xrd_index[(group, kind)] = (xrd_path, xrd_doc)

    # Match compositions to XRDs
    entries: list[PackageEntry] = []
    unmatched_compositions: list[str] = []
    matched_xrd_keys: set[tuple[str, str]] = set()

    # Auto-discover functions.yaml if not provided
    effective_functions = functions_path
    if not effective_functions and discovered_functions:
        # Look for a file named "functions.yaml" or "functions.yml"
        for fp in discovered_functions:
            if Path(fp).name in ("functions.yaml", "functions.yml"):
                effective_functions = fp
                break

    for comp_path, comp_doc in compositions:
        comp_spec = comp_doc.get("spec", {})
        type_ref = comp_spec.get("compositeTypeRef", {})
        api_ver = type_ref.get("apiVersion", "")
        ref_group = api_ver.split("/")[0] if "/" in api_ver else api_ver
        ref_kind = type_ref.get("kind", "")

        matched_xrd = xrd_index.get((ref_group, ref_kind))
        if matched_xrd:
            xrd_path_str, xrd_doc = matched_xrd
            matched_xrd_keys.add((ref_group, ref_kind))
            comp_name = comp_doc.get("metadata", {}).get("name", Path(comp_path).stem)
            xrd_name = xrd_doc.get("metadata", {}).get("name", Path(xrd_path_str).stem)

            entries.append(PackageEntry(
                composition_path=comp_path,
                composition_name=comp_name,
                xrd_path=xrd_path_str,
                xrd_name=xrd_name,
                functions_path=effective_functions,
                environment_config_paths=environment_config_paths or [],
            ))
        else:
            unmatched_compositions.append(comp_path)

    unmatched_xrds = [
        path for path, doc in xrds
        if (
            doc.get("spec", {}).get("group", ""),
            doc.get("spec", {}).get("names", {}).get("kind", ""),
        ) not in matched_xrd_keys
    ]

    duration = time.monotonic() - start
    return PackageScanResult(
        entries=entries,
        unmatched_compositions=unmatched_compositions,
        unmatched_xrds=unmatched_xrds,
        scan_duration_s=duration,
    )
