"""Core data models shared across all layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


class CompositionMode(str, Enum):
    RESOURCES = "Resources"
    PIPELINE = "Pipeline"


class RenderMode(str, Enum):
    """How composed resources were obtained from the composition."""

    STATIC_PARSE = "static_parse"  # Parsed directly from YAML (Resources mode, PaT)
    RENDER = "render"  # Rendered through crossplane render (go-templating)
    DEGRADED_PARSE = "degraded_parse"  # Go template sanitized — may be incomplete


@dataclass
class Finding:
    """A single validation finding emitted by any layer."""

    layer: int
    rule: str
    resource: str  # composed resource name, or "" for composition-level findings
    path: str  # dot-path or field path that triggered the finding
    severity: Severity
    message: str
    remediation: str
    # Optional metadata for advanced/offline analysis modules.
    finding_id: str = ""
    category: str = ""
    case_id: str = ""
    baseline_case_id: str = ""
    perturbation_id: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class ComposedResource:
    """A single composed resource template extracted from a Composition."""

    name: str  # spec.resources[].name or equivalent in Pipeline mode
    api_version: str
    kind: str
    # Raw spec.forProvider / spec body as parsed from the template
    spec: dict[str, Any] = field(default_factory=dict)
    # Patch entries as-is from the Composition YAML
    patches: list[dict[str, Any]] = field(default_factory=list)
    # readinessChecks entries (may be empty)
    readiness_checks: list[dict[str, Any]] = field(default_factory=list)
    # Selector fields (matchLabels / matchControllerRef)
    selector: dict[str, Any] | None = None
    # Go template expressions extracted from inline templates (field paths, variables)
    template_expressions: list[str] = field(default_factory=list)


@dataclass
class CompositionObject:
    """Parsed representation of one Crossplane Composition + its XRD."""

    # Metadata
    composition_name: str
    composition_path: str
    xrd_name: str
    xrd_path: str

    # Detected execution mode
    mode: CompositionMode

    # Composed resource templates
    resources: list[ComposedResource] = field(default_factory=list)

    # Raw XRD spec (for schema validation in Layer 1)
    xrd_spec: dict[str, Any] = field(default_factory=dict)

    # Path to the CRD bundle directory (read from config)
    crd_bundle_path: str = ""

    # EnvironmentConfig fixture paths supplied at load time
    environment_config_paths: list[str] = field(default_factory=list)

    # How resources were obtained (static parse, render, or degraded)
    render_mode: RenderMode = RenderMode.STATIC_PARSE
