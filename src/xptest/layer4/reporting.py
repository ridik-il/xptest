"""Layer 4 — Reporting.

Aggregates findings from all layers into:
  - A structured JSON file (findings.json by default).
  - A human-readable plain-text summary to stdout/stderr.
  - An exit code: 1 if any CRITICAL finding is present, 0 otherwise.

Finding schema (from framework-design.md §3.4):
  {layer, rule, resource, path, severity, message, remediation}
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import TextIO

from xptest.models import Finding, Severity


def write(
    findings: list[Finding],
    output_path: str = "findings.json",
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Write findings to JSON and print a plain-text summary.

    Returns:
        0 if no CRITICAL findings, 1 otherwise.
    """
    _write_json(findings, output_path)
    _print_summary(findings, stdout, stderr)
    return 1 if any(f.severity == Severity.CRITICAL for f in findings) else 0


def _write_json(findings: list[Finding], output_path: str) -> None:
    serializable = [{**asdict(f), "severity": f.severity.value} for f in findings]
    Path(output_path).write_text(
        json.dumps(serializable, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _print_summary(
    findings: list[Finding],
    stdout: TextIO,
    stderr: TextIO,
) -> None:
    criticals = [f for f in findings if f.severity == Severity.CRITICAL]
    warnings = [f for f in findings if f.severity == Severity.WARNING]
    infos = [f for f in findings if f.severity == Severity.INFO]

    total = len(findings)
    if total == 0:
        stdout.write("xptest: no findings — composition passed all checks.\n")
        return

    out = stdout if not criticals else stderr

    out.write(
        f"xptest: {total} finding(s) — "
        f"{len(criticals)} CRITICAL, {len(warnings)} WARNING, {len(infos)} INFO\n"
    )
    out.write("-" * 72 + "\n")

    for f in sorted(findings, key=lambda x: (x.severity.value, x.layer, x.resource)):
        out.write(f"[{f.severity.value}] Layer {f.layer} / {f.rule}\n")
        out.write(f"  Resource   : {f.resource or '(composition)'}\n")
        out.write(f"  Path       : {f.path}\n")
        out.write(f"  Message    : {f.message}\n")
        out.write(f"  Remediation: {f.remediation}\n")
        out.write("\n")
