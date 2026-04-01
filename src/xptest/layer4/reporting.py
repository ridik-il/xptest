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


def write_extended(
    findings: list[Finding],
    output_path: str,
    extra_sections: dict,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    payload = {
        "findings": [{**asdict(f), "severity": f.severity.value} for f in findings],
        "sections": extra_sections,
    }
    Path(output_path).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    _print_summary(findings, stdout, stderr)
    _print_extended_summary(extra_sections, stdout, stderr)
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


def _print_extended_summary(extra_sections: dict, stdout: TextIO, stderr: TextIO) -> None:
    out = stderr if extra_sections.get("critical_count", 0) else stdout
    logic = extra_sections.get("logic", {})
    if logic:
        out.write("xptest: logic testing summary\n")
        coverage = logic.get("coverage", {})
        line = (
            "  cases={cases} unique_graphs={graphs} "
            "unique_presence={presence} unique_fields={fields}\n"
        )
        out.write(
            line.format(
                cases=coverage.get("total_cases", 0),
                graphs=coverage.get("unique_graphs", 0),
                presence=coverage.get("unique_presence_signatures", 0),
                fields=coverage.get("unique_field_signatures", 0),
            )
        )
        out.write(
            f"  nearby_pairs={logic.get('nearby_pairs', 0)} "
            f"logic_findings={logic.get('logic_finding_count', 0)}\n"
        )

    timings = extra_sections.get("timings", {})
    if timings:
        out.write("xptest: timing breakdown\n")
        for key, val in timings.items():
            if isinstance(val, (int, float)):
                out.write(f"  {key}={val:.1f}s\n")

    perturb = extra_sections.get("perturbation", {})
    if perturb:
        out.write("xptest: perturbation summary\n")
        out.write(
            f"  scenarios={perturb.get('scenario_count', 0)} "
            f"findings={perturb.get('finding_count', 0)}\n"
        )
        dedup = perturb.get("dedup_skipped", 0)
        if dedup:
            out.write(
                f"  unique_baselines={perturb.get('unique_baselines', 0)} dedup_skipped={dedup}\n"
            )
        duration = perturb.get("duration_s", 0)
        if duration:
            out.write(f"  perturbation_duration={duration:.1f}s\n")

        # Summarise which scenario categories found actual issues
        scenarios = perturb.get("scenarios", [])
        if scenarios:
            by_kind: dict[str, tuple[int, int]] = {}  # kind -> (total, with_findings)
            for sc in scenarios:
                k = sc.get("perturbation_id", "unknown")
                total, found = by_kind.get(k, (0, 0))
                fc = sc.get("finding_count", 0)
                by_kind[k] = (total + 1, found + (1 if fc > 0 else 0))
            out.write("  scenario signal:\n")
            for k, (total, found) in sorted(by_kind.items()):
                signal = "HIT" if found else "no-signal"
                out.write(f"    {k}: {found}/{total} [{signal}]\n")

    exploration = extra_sections.get("exploration", {})
    if exploration:
        out.write("xptest: exploration summary\n")
        out.write(
            f"  inputs={exploration.get('total_inputs', 0)} "
            f"renders={exploration.get('successful_renders', 0)} "
            f"fault_renders={exploration.get('fault_injection_renders', 0)}\n"
        )
        out.write(
            f"  breaking_changes={exploration.get('breaking_change_count', 0)} "
            f"invariants={exploration.get('invariant_count', 0)} "
            f"fault_findings={exploration.get('fault_injection_count', 0)}\n"
        )
        tc = exploration.get("template_coverage", {})
        if tc:
            out.write(
                f"  template_coverage={tc.get('coverage_pct', 0):.1f}% "
                f"({tc.get('covered_branches', 0)}/{tc.get('total_branches', 0)} branches)\n"
            )
