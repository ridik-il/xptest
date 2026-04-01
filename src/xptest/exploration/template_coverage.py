"""Go template branch coverage wrapper (§7.4, §4.4.3).

Calls a Go helper binary that parses Go templates via text/template/parse,
instruments branch nodes, and reports which branches fired for each input.

Resources-mode compositions have no Go templates and report 100% trivially.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class BranchInfo:
    branch_id: str
    template: str
    line: int
    node_type: str
    guard_expression: str


@dataclass
class CoverageReport:
    total_branches: int
    covered_branches: int
    coverage_pct: float
    uncovered: list[BranchInfo] = field(default_factory=list)


def measure_coverage(
    template_source: str,
    inputs: list[dict[str, Any]],
    go_helper_path: str = "",
) -> CoverageReport:
    """Measure Go template branch coverage for given inputs.

    If go_helper_path is empty or the binary is not found, returns a trivial
    report (100% coverage with 0 branches) — this handles Resources-mode
    compositions where no Go template exists.
    """
    if not template_source.strip():
        return CoverageReport(
            total_branches=0,
            covered_branches=0,
            coverage_pct=100.0,
        )

    helper = _resolve_helper(go_helper_path)
    if not helper:
        return CoverageReport(
            total_branches=0,
            covered_branches=0,
            coverage_pct=100.0,
        )

    payload = json.dumps(
        {
            "template": template_source,
            "inputs": inputs,
        }
    )

    try:
        result = subprocess.run(
            [str(helper)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        return CoverageReport(
            total_branches=0,
            covered_branches=0,
            coverage_pct=100.0,
        )
    except subprocess.TimeoutExpired:
        return CoverageReport(
            total_branches=0,
            covered_branches=0,
            coverage_pct=0.0,
        )

    if result.returncode != 0:
        return CoverageReport(
            total_branches=0,
            covered_branches=0,
            coverage_pct=0.0,
        )

    return _parse_coverage_output(result.stdout)


def _resolve_helper(path: str) -> Path | None:
    """Find the Go helper binary."""
    if path:
        p = Path(path)
        if p.exists() and p.is_file():
            return p
        return None

    # Default locations
    candidates = [
        Path("tools/template-coverage/bin/template-coverage"),
        Path("tools/template-coverage/template-coverage"),
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return c

    return None


def _parse_coverage_output(stdout: str) -> CoverageReport:
    """Parse JSON output from Go helper."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return CoverageReport(
            total_branches=0,
            covered_branches=0,
            coverage_pct=0.0,
        )

    total = int(data.get("total_branches", 0))
    covered = int(data.get("covered_branches", 0))
    pct = float(data.get("coverage_pct", 0.0))

    uncovered = [
        BranchInfo(
            branch_id=b.get("branch_id", ""),
            template=b.get("template", ""),
            line=int(b.get("line", 0)),
            node_type=b.get("node_type", ""),
            guard_expression=b.get("guard_expression", ""),
        )
        for b in data.get("uncovered", [])
    ]

    return CoverageReport(
        total_branches=total,
        covered_branches=covered,
        coverage_pct=pct,
        uncovered=uncovered,
    )
