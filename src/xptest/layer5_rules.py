"""Layer 5 — Extended validation rules.

Standalone functions that operate on rendered resources and environment config
data, returning lists of Finding objects.  Each function is self-contained and
can be called independently.
"""

from __future__ import annotations

import ipaddress
import logging
import tempfile
from pathlib import Path
from typing import Any

import yaml

from xptest.models import Finding, Severity

logger = logging.getLogger(__name__)

_LAYER = 6

# Security-sensitive resource kinds whose structural differences across
# envconfigs warrant a finding.
_SECURITY_KINDS = {"SecurityGroup", "SecurityGroupRule", "Role", "RolePolicy", "Policy"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_envconfig_data(envconfig_paths: list[str]) -> dict[str, Any]:
    """Merge data fields from all EnvironmentConfig docs across paths."""
    merged: dict[str, Any] = {}
    for path in envconfig_paths:
        for doc in yaml.safe_load_all(Path(path).read_text()):
            if isinstance(doc, dict) and doc.get("kind") == "EnvironmentConfig":
                merged.update(doc.get("data", {}))
    return merged


def _render_to_docs(
    composition_path: str,
    xrd_path: str,
    functions_path: str,
    xr_doc: dict,
    envconfig_paths: list[str],
    observed_resources_path: str | None = None,
) -> list[dict]:
    """Render a composition and return parsed YAML docs."""
    from xptest.render import render_composition

    comp_doc = yaml.safe_load(Path(composition_path).read_text())
    if functions_path and Path(functions_path).exists():
        functions_yaml = Path(functions_path).read_text()
    else:
        from xptest.render import generate_functions_yaml

        func_docs = generate_functions_yaml(comp_doc)
        functions_yaml = yaml.dump_all(func_docs, default_flow_style=False)

    xr_yaml = yaml.dump(xr_doc, default_flow_style=False)
    raw = render_composition(
        composition_path=composition_path,
        xr_yaml=xr_yaml,
        functions_yaml=functions_yaml,
        environment_config_paths=envconfig_paths,
        observed_resources_path=observed_resources_path,
    )
    return [d for d in yaml.safe_load_all(raw) if isinstance(d, dict)]


def _resource_key(doc: dict) -> str:
    """Stable identity key for a rendered resource."""
    meta = doc.get("metadata", {})
    ann = meta.get("annotations", {})
    comp_name = ann.get("crossplane.io/composition-resource-name", "")
    return f"{doc.get('kind', '?')}/{comp_name or meta.get('name', '?')}"


# ---------------------------------------------------------------------------
# Feature 1: EnvironmentConfig coverage matrix
# ---------------------------------------------------------------------------


def check_env_matrix(
    composition_path: str,
    xrd_path: str,
    functions_path: str,
    xr_doc: dict,
    envconfig_paths: list[str],
) -> list[Finding]:
    """Render with each envconfig and compare for structural/security divergence."""
    if len(envconfig_paths) < 2:
        return []

    findings: list[Finding] = []
    renders: dict[str, set[str]] = {}
    kind_sets: dict[str, set[str]] = {}

    for ec_path in envconfig_paths:
        label = Path(ec_path).stem
        try:
            docs = _render_to_docs(composition_path, xrd_path, functions_path, xr_doc, [ec_path])
        except Exception as exc:
            logger.warning("env-matrix render failed for %s: %s", label, exc)
            findings.append(
                Finding(
                    layer=_LAYER,
                    rule="L6-ENV-01",
                    resource="",
                    path=ec_path,
                    severity=Severity.WARNING,
                    message=f"Render failed for envconfig '{label}': {exc}",
                    remediation="Check that the envconfig is valid for this composition.",
                )
            )
            continue
        keys = {_resource_key(d) for d in docs}
        kinds = {d.get("kind", "") for d in docs}
        renders[label] = keys
        kind_sets[label] = kinds

    if len(renders) < 2:
        return findings

    # Compare all pairs for structural differences
    labels = sorted(renders)
    base_label = labels[0]
    base_keys = renders[base_label]

    for label in labels[1:]:
        other_keys = renders[label]
        only_base = base_keys - other_keys
        only_other = other_keys - base_keys
        if only_base or only_other:
            detail_parts = []
            if only_base:
                detail_parts.append(f"only in {base_label}: {sorted(only_base)}")
            if only_other:
                detail_parts.append(f"only in {label}: {sorted(only_other)}")
            findings.append(
                Finding(
                    layer=_LAYER,
                    rule="L6-ENV-01",
                    resource="",
                    path="envconfig-matrix",
                    severity=Severity.WARNING,
                    message=(
                        f"Structural divergence between '{base_label}' and '{label}': "
                        + "; ".join(detail_parts)
                    ),
                    remediation=(
                        "Verify that resource presence/absence across environments is intentional."
                    ),
                )
            )

        # Flag security-sensitive kind differences
        sec_base = base_keys & {k for k in base_keys if k.split("/")[0] in _SECURITY_KINDS}
        sec_other = other_keys & {k for k in other_keys if k.split("/")[0] in _SECURITY_KINDS}
        sec_diff = sec_base.symmetric_difference(sec_other)
        if sec_diff:
            findings.append(
                Finding(
                    layer=_LAYER,
                    rule="L6-ENV-01",
                    resource="",
                    path="envconfig-matrix/security",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Security-sensitive resources differ between '{base_label}' "
                        f"and '{label}': {sorted(sec_diff)}"
                    ),
                    remediation=(
                        "Security group or IAM resources should be consistent across "
                        "environments unless explicitly intended."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Feature 2: Security group / network reachability
# ---------------------------------------------------------------------------


def check_sg_reachability(
    rendered_resources: list[dict],
    env_config_data: dict,
) -> list[Finding]:
    """Check that SG ingress CIDRs cover VPC non-routable and routable subnets."""
    findings: list[Finding] = []

    # Collect subnet CIDRs from envconfig
    nr_cidrs: list[ipaddress.IPv4Network] = []
    r_cidrs: list[ipaddress.IPv4Network] = []
    for key, val in env_config_data.items():
        try:
            if key.startswith("vpcSubnetPrivateNonRoutableCidr"):
                nr_cidrs.append(ipaddress.IPv4Network(val, strict=False))
            elif key.startswith("vpcSubnetPrivateRoutableCidr"):
                r_cidrs.append(ipaddress.IPv4Network(val, strict=False))
        except (ValueError, TypeError):
            continue

    if not nr_cidrs and not r_cidrs:
        return findings

    all_subnet_cidrs = nr_cidrs + r_cidrs

    for res in rendered_resources:
        kind = res.get("kind", "")
        if "SecurityGroup" not in kind:
            continue

        resource_name = _resource_key(res)
        spec = res.get("spec", {})
        fp = spec.get("forProvider", {})

        # Check ingress rules — try spec.forProvider.ingress first, fall back
        # to spec.ingress (used by composite XSecurityGroup resources).
        ingress_rules = fp.get("ingress", []) or spec.get("ingress", [])
        ingress_path = "spec.forProvider.ingress" if fp.get("ingress") else "spec.ingress"
        if not ingress_rules:
            continue

        # Collect all ingress CIDRs
        ingress_nets: list[ipaddress.IPv4Network] = []
        for rule in ingress_rules:
            for cidr_block in rule.get("cidrBlocks", []):
                try:
                    ingress_nets.append(ipaddress.IPv4Network(cidr_block, strict=False))
                except (ValueError, TypeError):
                    continue
            # Also check ipRanges (alternative field name)
            for ip_range in rule.get("ipRanges", []):
                cidr = ip_range.get("cidrIp", "") if isinstance(ip_range, dict) else ip_range
                try:
                    ingress_nets.append(ipaddress.IPv4Network(cidr, strict=False))
                except (ValueError, TypeError):
                    continue

        if not ingress_nets:
            continue

        # Check coverage: each subnet CIDR should be contained by at least one ingress CIDR
        for subnet in all_subnet_cidrs:
            covered = any(subnet.subnet_of(ingress) for ingress in ingress_nets)
            if not covered:
                subnet_type = "non-routable" if subnet in nr_cidrs else "routable"
                findings.append(
                    Finding(
                        layer=_LAYER,
                        rule="L6-NET-01",
                        resource=resource_name,
                        path=ingress_path,
                        severity=Severity.CRITICAL,
                        message=(
                            f"SecurityGroup ingress does not cover {subnet_type} "
                            f"subnet {subnet}. Ingress CIDRs: "
                            f"{[str(n) for n in ingress_nets]}"
                        ),
                        remediation=(
                            f"Add {subnet} (or a supernet) to the SecurityGroup ingress rules "
                            "to ensure VPC connectivity."
                        ),
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Feature 3: Multi-render-cycle simulation
# ---------------------------------------------------------------------------


def _build_observed_yaml(docs: list[dict]) -> str:
    """Build observed-resources YAML with all resources marked READY."""
    observed: list[dict] = []
    for doc in docs:
        meta = doc.get("metadata", {})
        ann = meta.get("annotations", {})
        comp_name = ann.get("crossplane.io/composition-resource-name", "")
        obs: dict[str, Any] = {
            "apiVersion": doc.get("apiVersion", ""),
            "kind": doc.get("kind", ""),
            "metadata": {
                "name": meta.get("name", "observed"),
                "annotations": {
                    "crossplane.io/composition-resource-name": comp_name,
                },
            },
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}],
            },
        }
        observed.append(obs)
    return yaml.dump_all(observed, default_flow_style=False)


def check_multi_render(
    composition_path: str,
    xrd_path: str,
    functions_path: str,
    xr_doc: dict,
    envconfig_paths: list[str],
) -> list[Finding]:
    """Simulate multiple render cycles and verify resource stability."""
    findings: list[Finding] = []
    num_cycles = 4

    prev_docs: list[dict] = []
    prev_keys: set[str] = set()

    for cycle in range(num_cycles):
        observed_path: str | None = None
        try:
            if prev_docs:
                observed_yaml = _build_observed_yaml(prev_docs)
                tmp = tempfile.NamedTemporaryFile(mode="w", suffix="-observed.yaml", delete=False)
                tmp.write(observed_yaml)
                tmp.close()
                observed_path = tmp.name

            docs = _render_to_docs(
                composition_path,
                xrd_path,
                functions_path,
                xr_doc,
                envconfig_paths,
                observed_resources_path=observed_path,
            )
        except Exception as exc:
            logger.warning("multi-render cycle %d failed: %s", cycle, exc)
            findings.append(
                Finding(
                    layer=_LAYER,
                    rule="L6-MRC-01",
                    resource="",
                    path=f"cycle-{cycle}",
                    severity=Severity.WARNING,
                    message=f"Render failed at cycle {cycle}: {exc}",
                    remediation="Check composition for render stability.",
                )
            )
            break
        finally:
            if observed_path:
                Path(observed_path).unlink(missing_ok=True)

        current_keys = {_resource_key(d) for d in docs}

        if cycle > 0:
            disappeared = prev_keys - current_keys
            if disappeared:
                findings.append(
                    Finding(
                        layer=_LAYER,
                        rule="L6-MRC-01",
                        resource="",
                        path=f"cycle-{cycle}",
                        severity=Severity.CRITICAL,
                        message=(
                            f"Resources disappeared in cycle {cycle} when dependencies "
                            f"became ready: {sorted(disappeared)}"
                        ),
                        remediation=(
                            "Ensure composition conditionals do not remove resources "
                            "when observed state changes."
                        ),
                    )
                )

            if len(current_keys) < len(prev_keys):
                findings.append(
                    Finding(
                        layer=_LAYER,
                        rule="L6-MRC-01",
                        resource="",
                        path=f"cycle-{cycle}",
                        severity=Severity.WARNING,
                        message=(
                            f"Resource count shrank from {len(prev_keys)} to "
                            f"{len(current_keys)} in cycle {cycle}."
                        ),
                        remediation="Verify resource lifecycle across render cycles.",
                    )
                )

        prev_docs = docs
        prev_keys = current_keys

    return findings


# ---------------------------------------------------------------------------
# Feature 4: Deletion policy consistency
# ---------------------------------------------------------------------------


def check_deletion_policy(
    rendered_resources: list[dict],
    xr_doc: dict,
) -> list[Finding]:
    """Check that all rendered resources inherit the XR's deletionPolicy."""
    findings: list[Finding] = []
    xr_policy = xr_doc.get("spec", {}).get("crossplaneParameters", {}).get("deletionPolicy", "")
    if not xr_policy:
        return findings

    for res in rendered_resources:
        resource_name = _resource_key(res)
        res_policy = res.get("spec", {}).get("deletionPolicy", "")
        if res_policy and res_policy != xr_policy:
            findings.append(
                Finding(
                    layer=_LAYER,
                    rule="L6-DEL-01",
                    resource=resource_name,
                    path="spec.deletionPolicy",
                    severity=Severity.WARNING,
                    message=(
                        f"Resource deletionPolicy '{res_policy}' does not match "
                        f"XR deletionPolicy '{xr_policy}'."
                    ),
                    remediation=(
                        "Ensure the composition propagates spec.crossplaneParameters."
                        "deletionPolicy to all managed resources."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Feature 5: Tag propagation
# ---------------------------------------------------------------------------

_DEFAULT_MANDATORY_TAGS = ["claim-name", "created-by"]


def check_tag_propagation(
    rendered_resources: list[dict],
    mandatory_keys: list[str] | None = None,
) -> list[Finding]:
    """Verify mandatory tags are present on every AWS resource with forProvider."""
    findings: list[Finding] = []
    keys = mandatory_keys or _DEFAULT_MANDATORY_TAGS

    for res in rendered_resources:
        fp = res.get("spec", {}).get("forProvider")
        if fp is None:
            continue

        resource_name = _resource_key(res)
        tags = fp.get("tags", {})

        # Tags can be a dict or a list of {key, value} pairs
        if isinstance(tags, list):
            tag_keys = {t.get("key", "") for t in tags if isinstance(t, dict)}
        elif isinstance(tags, dict):
            tag_keys = set(tags.keys())
        else:
            tag_keys = set()

        missing = [k for k in keys if k not in tag_keys]
        if missing:
            findings.append(
                Finding(
                    layer=_LAYER,
                    rule="L6-TAG-01",
                    resource=resource_name,
                    path="spec.forProvider.tags",
                    severity=Severity.WARNING,
                    message=f"Missing mandatory tags: {missing}",
                    remediation=(
                        "Add the missing tags to the composition template or "
                        "patch-and-transform configuration."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Feature 6: Cross-composition dependency validation
# ---------------------------------------------------------------------------


def check_cross_composition(
    rendered_resources: list[dict],
    env_config_data: dict,
) -> list[Finding]:
    """Check that providerConfigRef names match known patterns from envconfig."""
    findings: list[Finding] = []

    # Build set of known provider config names from envconfig
    known_configs: set[str] = set()
    crossplane_data = env_config_data.get("crossplane", {})
    if isinstance(crossplane_data, dict):
        providers = crossplane_data.get("providers", {})
        if isinstance(providers, dict):
            for prov_info in providers.values():
                if isinstance(prov_info, dict):
                    ref = prov_info.get("configRef", "")
                    if ref:
                        known_configs.add(ref)

    if not known_configs:
        return findings

    for res in rendered_resources:
        resource_name = _resource_key(res)
        spec = res.get("spec", {})
        pcr = spec.get("providerConfigRef", {})
        if not isinstance(pcr, dict):
            continue
        pcr_name = pcr.get("name", "")
        if not pcr_name:
            continue

        if pcr_name not in known_configs:
            findings.append(
                Finding(
                    layer=_LAYER,
                    rule="L6-XCC-01",
                    resource=resource_name,
                    path="spec.providerConfigRef.name",
                    severity=Severity.WARNING,
                    message=(
                        f"providerConfigRef '{pcr_name}' not found in envconfig "
                        f"known configs: {sorted(known_configs)}"
                    ),
                    remediation=(
                        "Verify the providerConfigRef matches a provider config "
                        "defined in the EnvironmentConfig."
                    ),
                )
            )

    return findings
