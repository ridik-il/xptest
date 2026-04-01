"""Layer 3 — Policy Compliance via OPA Rego (full document evaluation mode).

Evaluates the entire composition resource graph against OPA Rego rules in a
single pass.  All composed resources are sent as a JSON input document so that
cross-resource rules can correlate fields across multiple resources.

Checks (from framework-design.md §3.3):
  Encryption:     enc/s3-sse, enc/rds-encrypted
  Network:        net/sg-no-open-ssh, net/sg-no-open-db, net/rds-not-public, net/s3-public-block
  IAM:            iam/no-wildcard-action, iam/no-wildcard-resource, iam/trust-service-match
  Cross-resource: cross/kms-key-consistency, cross/iam-rds-trust, cross/sg-rds-port-match
  Tagging:        tag/mandatory-keys

Requires: OPA binary on PATH or configured via opa_binary in xptest.yaml.
No AWS credentials.  No live cluster.
Execution target: < 10 seconds for typical compositions.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from xptest.config import Config
from xptest.models import CompositionObject, Finding, Severity

# OPA packages that contain violations sets
_RULE_PACKAGES = [
    "xptest.encryption",
    "xptest.network",
    "xptest.iam",
    "xptest.cross_resource",
    "xptest.tagging",
]


class OpaError(RuntimeError):
    pass


def run(obj: CompositionObject, config: Config) -> list[Finding]:
    """Evaluate all Rego rules against the composition and return findings."""
    if not config.rules_path:
        return []

    rules_dir = Path(config.rules_path)
    if not rules_dir.is_dir():
        return []

    findings: list[Finding] = []

    # Decision 1: enforce pinned OPA version when configured
    if config.opa_expected_version:
        version_finding = _check_opa_version(config)
        if version_finding:
            findings.append(version_finding)

    opa_input = _build_input(obj, config)
    raw_violations = _evaluate_opa(opa_input, rules_dir, config)
    findings.extend(_violations_to_findings(raw_violations, config))
    return findings


def _check_opa_version(config: Config) -> Finding | None:
    """Verify that the running OPA version matches the pinned version.

    Design ref: framework-design.md Decision 1 — pinned OPA version.
    Returns a WARNING finding on mismatch, None if versions match.
    """
    import re as _re

    try:
        result = subprocess.run(
            [config.opa_binary, "version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None  # OPA binary issue will be caught later during eval

    # OPA version output: "Version: 0.60.0" or similar
    match = _re.search(r"Version:\s*(\S+)", result.stdout)
    if not match:
        return None

    actual_version = match.group(1)
    expected = config.opa_expected_version.strip()

    if actual_version == expected:
        return None

    return Finding(
        layer=3,
        rule="L3-01/opa-version-mismatch",
        resource="",
        path="opa_expected_version",
        severity=Severity.WARNING,
        message=(
            f"OPA binary version '{actual_version}' does not match "
            f"pinned version '{expected}'. Policy evaluation may produce "
            "different results than expected."
        ),
        remediation=(
            f"Install OPA version {expected} or update opa_expected_version in xptest.yaml."
        ),
    )


def _build_input(obj: CompositionObject, config: Config) -> dict[str, Any]:
    """Build the JSON input document for OPA evaluation.

    Structure:
        {
            "resources": [ ... composed resources ... ],
            "config": {
                "mandatory_tag_keys": [...]
            }
        }
    """
    resources = []
    for r in obj.resources:
        resources.append(
            {
                "name": r.name,
                "apiVersion": r.api_version,
                "kind": r.kind,
                "spec": r.spec,
            }
        )

    return {
        "resources": resources,
        "config": {
            "mandatory_tag_keys": config.mandatory_tag_keys,
        },
    }


def _evaluate_opa(
    opa_input: dict[str, Any],
    rules_dir: Path,
    config: Config,
) -> list[dict[str, Any]]:
    """Call OPA to evaluate all rule packages and collect violations.

    Uses a single OPA eval call with a combined query to avoid 5 sequential
    subprocess invocations.
    """
    all_violations: list[dict[str, Any]] = []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as input_file:
        json.dump(opa_input, input_file)
        input_path = input_file.name

    try:
        # Try combined query first (single subprocess call)
        combined_parts = [f"data.{pkg}.violations" for pkg in _RULE_PACKAGES]
        combined_query = "[" + ", ".join(combined_parts) + "]"
        combined = _run_opa_combined_query(
            config.opa_binary, input_path, str(rules_dir), combined_query
        )
        if combined is not None:
            all_violations.extend(combined)
        else:
            # Fallback: individual queries (backwards compatible)
            for package in _RULE_PACKAGES:
                query = f"data.{package}.violations"
                violations = _run_opa_query(config.opa_binary, input_path, str(rules_dir), query)
                all_violations.extend(violations)
    finally:
        Path(input_path).unlink(missing_ok=True)

    return all_violations


def _run_opa_combined_query(
    opa_binary: str,
    input_path: str,
    data_dir: str,
    query: str,
) -> list[dict[str, Any]] | None:
    """Run a combined OPA query returning all violations. Returns None on failure."""
    cmd = [
        opa_binary,
        "eval",
        "--data",
        data_dir,
        "--input",
        input_path,
        "--format",
        "json",
        query,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None

    # Combined query returns: {"result": [{"expressions": [{"value": [[...], [...], ...]}]}]}
    violations: list[dict[str, Any]] = []
    for r in output.get("result", []):
        for expr in r.get("expressions", []):
            value = expr.get("value")
            if isinstance(value, list):
                for pkg_violations in value:
                    if isinstance(pkg_violations, list):
                        violations.extend(pkg_violations)
                    elif isinstance(pkg_violations, dict):
                        violations.append(pkg_violations)
    return violations


def _run_opa_query(
    opa_binary: str,
    input_path: str,
    data_dir: str,
    query: str,
) -> list[dict[str, Any]]:
    """Run a single OPA eval query and return the result set."""
    cmd = [
        opa_binary,
        "eval",
        "--data",
        data_dir,
        "--input",
        input_path,
        "--format",
        "json",
        query,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except FileNotFoundError:
        raise OpaError(
            f"OPA binary '{opa_binary}' not found. Install OPA or set opa_binary in xptest.yaml."
        ) from None
    except subprocess.TimeoutExpired:
        raise OpaError(f"OPA evaluation timed out for query: {query}") from None

    if result.returncode != 0:
        # OPA returns non-zero for undefined results (no violations) — that's OK
        if "undefined" in result.stderr.lower():
            return []
        # Filter out warning lines (version notices, deprecation) from real errors
        stderr_lines = result.stderr.strip().splitlines()
        error_lines = [
            ln
            for ln in stderr_lines
            if not ln.lower().startswith("warning:") and "deprecated" not in ln.lower()
        ]
        error_msg = "\n".join(error_lines).strip() or result.stderr.strip()
        raise OpaError(f"OPA evaluation failed (exit {result.returncode}): {error_msg}")

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise OpaError(f"OPA returned invalid JSON: {result.stdout[:200]}") from None

    # OPA eval output structure: {"result": [{"expressions": [{"value": [...]}]}]}
    violations = []
    for r in output.get("result", []):
        for expr in r.get("expressions", []):
            value = expr.get("value")
            if isinstance(value, list):
                violations.extend(value)
            elif isinstance(value, set):
                violations.extend(value)
    return violations


def _violations_to_findings(
    violations: list[dict[str, Any]],
    config: Config,
) -> list[Finding]:
    """Convert raw OPA violation dicts to Finding objects."""
    findings: list[Finding] = []
    for v in violations:
        rule_id = v.get("rule", "unknown")
        # Apply severity override from config, or use the Rego-specified severity
        raw_severity = config.severity_overrides.get(rule_id, v.get("severity", "CRITICAL"))
        severity = _parse_severity(raw_severity)

        findings.append(
            Finding(
                layer=3,
                rule=rule_id,
                resource=v.get("resource", ""),
                path=v.get("path", ""),
                severity=severity,
                message=v.get("message", ""),
                remediation=v.get("remediation", ""),
            )
        )
    return findings


def _parse_severity(raw: str) -> Severity:
    upper = raw.upper()
    try:
        return Severity(upper)
    except ValueError:
        return Severity.CRITICAL
