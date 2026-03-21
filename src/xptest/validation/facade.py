"""Shared facade to execute existing Layer 1/2/3 validators consistently."""

from __future__ import annotations

from dataclasses import dataclass

from xptest.config import Config
from xptest.layer1 import static as layer1
from xptest.layer2 import dependency as layer2
from xptest.layer3 import policy as layer3
from xptest.models import CompositionObject, Finding, Severity


@dataclass
class ValidationRunResult:
    findings: list[Finding]
    halted_layer: int | None = None


def run_validations(
    obj: CompositionObject,
    cfg: Config,
    halt_on_critical: bool = True,
) -> ValidationRunResult:
    findings: list[Finding] = []

    l1_findings = layer1.run(obj)
    findings.extend(l1_findings)
    if halt_on_critical and _has_critical(l1_findings):
        return ValidationRunResult(findings=findings, halted_layer=1)

    l2_findings = layer2.run(obj)
    findings.extend(l2_findings)
    if halt_on_critical and _has_critical(l2_findings):
        return ValidationRunResult(findings=findings, halted_layer=2)

    try:
        l3_findings = layer3.run(obj, cfg)
        findings.extend(l3_findings)
    except layer3.OpaError as exc:
        findings.append(
            Finding(
                layer=3,
                rule="L3-00/opa-runtime-error",
                resource="",
                path="",
                severity=Severity.WARNING,
                message=f"OPA evaluation skipped due to runtime error: {exc}",
                remediation="Install OPA correctly or validate rules_path and opa_binary.",
                finding_id="l3_opa_runtime_error",
                category="policy-runtime",
                evidence={"error": str(exc)},
            )
        )

    return ValidationRunResult(findings=findings, halted_layer=None)


def _has_critical(findings: list[Finding]) -> bool:
    return any(f.severity == Severity.CRITICAL for f in findings)
