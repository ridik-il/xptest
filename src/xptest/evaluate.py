"""Evaluation runner — execute the full pipeline on all fixtures and collect metrics.

Usage (as module):
    python -m xptest.evaluate [--fixtures-dir <path>] [--output <path>]

Runs Layers 1+2 on all fixtures. Layer 3 is included only if OPA is available
and a rules_path is configured.

Outputs evaluation-report.json with per-layer and per-fixture metrics.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from xptest.config import Config, load_config
from xptest.layer1 import static as layer1
from xptest.layer2 import dependency as layer2
from xptest.loader import load
from xptest.metrics import (
    aggregate_by_layer,
    compute_fixture_metrics,
    generate_report,
)


def _collect_fixtures(fixtures_dir: Path) -> list[tuple[str, Path, str]]:
    """Return (stem, yaml_path, subdir) for all fixtures with expected.json."""
    results = []
    for subdir in ("valid", "dep-errors", "policy-violations"):
        d = fixtures_dir / subdir
        if not d.is_dir():
            continue
        for yaml_file in sorted(d.glob("*.yaml")):
            expected = yaml_file.with_name(yaml_file.stem + "-expected.json")
            if expected.exists():
                results.append((yaml_file.stem, yaml_file, subdir))
    return results


def _run_pipeline(
    fixture_path: Path,
    xrd_path: str,
    config: Config,
) -> list[dict]:
    """Run Layers 1+2 (and optionally 3) on a fixture. Return findings as dicts."""
    obj = load(str(fixture_path), xrd_path)

    findings = layer1.run(obj) + layer2.run(obj)

    # Try Layer 3 if configured
    if config.rules_path:
        try:
            from xptest.layer3 import policy as layer3

            l3_findings = layer3.run(obj, config)
            findings.extend(l3_findings)
        except Exception:
            pass  # OPA not available — skip L3

    return [
        {
            "layer": f.layer,
            "rule": f.rule,
            "resource": f.resource,
            "path": f.path,
            "severity": f.severity.value,
            "message": f.message,
            "remediation": f.remediation,
        }
        for f in findings
    ]


def run_evaluation(
    fixtures_dir: Path,
    xrd_path: str,
    config: Config,
    output_path: str = "evaluation-report.json",
) -> dict:
    """Run evaluation across all fixtures and write report."""
    fixtures = _collect_fixtures(fixtures_dir)
    findings_by_fixture: dict[str, list[dict]] = {}

    for stem, yaml_path, subdir in fixtures:
        try:
            findings = _run_pipeline(yaml_path, xrd_path, config)
            findings_by_fixture[stem] = findings
        except Exception as exc:
            findings_by_fixture[stem] = []
            sys.stderr.write(f"  ERROR on {stem}: {exc}\n")

    fixture_results = compute_fixture_metrics(fixtures_dir, findings_by_fixture)
    layer_metrics = aggregate_by_layer(
        fixture_results, findings_by_fixture, fixtures_dir
    )
    report = generate_report(layer_metrics, fixture_results)

    Path(output_path).write_text(json.dumps(report, indent=2) + "\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run xptest evaluation across all fixtures."
    )
    parser.add_argument(
        "--fixtures-dir",
        default=None,
        help="Path to fixtures directory (default: ./fixtures)",
    )
    parser.add_argument(
        "--xrd",
        default=None,
        help="Path to XRD YAML (default: fixtures/xrd.yaml)",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to xptest.yaml config.",
    )
    parser.add_argument(
        "--output",
        default="evaluation-report.json",
        help="Output path for evaluation report JSON.",
    )
    args = parser.parse_args(argv)

    fixtures_dir = Path(args.fixtures_dir) if args.fixtures_dir else Path("fixtures")
    xrd_path = args.xrd or str(fixtures_dir / "xrd.yaml")

    config = load_config(args.config)

    report = run_evaluation(fixtures_dir, xrd_path, config, args.output)

    # Print summary
    print("\n=== Evaluation Summary ===")
    for layer_num, lm in sorted(report["summary"].items()):
        print(
            f"  Layer {lm['layer']}: "
            f"TP={lm['tp']} FP={lm['fp']} FN={lm['fn']} "
            f"Recall={lm['recall']:.2%} Precision={lm['precision']:.2%} "
            f"FPR={lm['fpr']:.2%}"
        )

    print("\n  Per-fixture details:")
    for fr in report["fixtures"]:
        status = "PASS" if fr["fn"] == 0 and fr["fp"] == 0 else "FAIL"
        detail = f" ({', '.join(fr['details'])})" if fr["details"] else ""
        print(
            f"    [{status}] {fr['fixture']}: "
            f"expected={fr['expected']} actual={fr['actual']} "
            f"TP={fr['tp']} FP={fr['fp']} FN={fr['fn']}{detail}"
        )

    print(f"\n  Report written to: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
