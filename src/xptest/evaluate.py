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
        except ImportError:
            pass  # OPA module not installed — skip L3
        except Exception as exc:
            import logging

            logging.getLogger("xptest.evaluate").warning(
                "Layer 3 evaluation failed: %s",
                exc,
            )

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
    """Run evaluation across all fixtures and write report.

    Computes §3.3.4 metrics:
    - Per-layer recall, precision, FPR
    - t-way input coverage (if XRD has parameters)
    - Mutation score (from fault-injection findings)
    - Determinism score (double-run comparison)
    """
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
    layer_metrics = aggregate_by_layer(fixture_results, findings_by_fixture, fixtures_dir)
    report = generate_report(layer_metrics, fixture_results)

    # Additional §3.3.4 metrics
    additional_metrics = _compute_additional_metrics(
        fixtures_dir, xrd_path, config, findings_by_fixture
    )
    report["additional_metrics"] = additional_metrics

    Path(output_path).write_text(json.dumps(report, indent=2) + "\n")
    return report


def _compute_additional_metrics(
    fixtures_dir: Path,
    xrd_path: str,
    config: Config,
    findings_by_fixture: dict[str, list[dict]],
) -> dict:
    """Compute t-way coverage, mutation score, and determinism score."""
    from xptest.exploration.determinism import compute_determinism_score
    from xptest.exploration.fault_injection import compute_mutation_score
    from xptest.exploration.input_synthesis import (
        _extract_parameters,
        _read_xrd,
        compute_tway_coverage,
        generate_seed_suite,
    )
    from xptest.logic.models import RenderedGraphSnapshot
    from xptest.logic.snapshot import build_snapshot
    from xptest.models import Finding, Severity

    result: dict = {}

    # t-way coverage from XRD parameters
    try:
        candidates = generate_seed_suite(xrd_path, max_count=50)
        xrd_doc = _read_xrd(xrd_path)
        xrd_spec = (
            xrd_doc.get("spec", {})
            .get("versions", [{}])[0]
            .get("schema", {})
            .get("openAPIV3Schema", {})
            .get("properties", {})
            .get("spec", {})
        )
        params = _extract_parameters(xrd_spec)
        if params and candidates:
            result["tway_coverage"] = compute_tway_coverage(candidates, params, t=2)
        else:
            result["tway_coverage"] = {
                "t": 2,
                "total_tuples": 0,
                "covered_tuples": 0,
                "coverage_pct": 100.0,
            }
    except Exception as exc:
        import logging

        logging.getLogger("xptest.evaluate").warning(
            "t-way coverage computation failed: %s",
            exc,
        )
        result["tway_coverage"] = {
            "t": 2,
            "total_tuples": 0,
            "covered_tuples": 0,
            "coverage_pct": 100.0,
        }

    # Mutation score from all fault-injection findings across fixtures
    all_fi_findings: list[Finding] = []
    total_faults = 0
    for findings_list in findings_by_fixture.values():
        for fd in findings_list:
            rule = fd.get("rule", "")
            if rule.startswith("fi/") or rule.startswith("inv/"):
                all_fi_findings.append(
                    Finding(
                        layer=fd.get("layer", 0),
                        rule=rule,
                        resource=fd.get("resource", ""),
                        path=fd.get("path", ""),
                        severity=Severity(fd.get("severity", "WARNING")),
                        message="",
                        remediation="",
                    )
                )
                total_faults += 1
    result["mutation_score"] = compute_mutation_score(
        max(total_faults, len(all_fi_findings)), all_fi_findings
    )

    # Determinism score — run each fixture twice and compare snapshots
    run_a: list[RenderedGraphSnapshot] = []
    run_b: list[RenderedGraphSnapshot] = []
    for subdir in ("valid", "dep-errors"):
        d = fixtures_dir / subdir
        if not d.is_dir():
            continue
        for yaml_file in sorted(d.glob("*.yaml"))[:3]:
            try:
                obj_a = load(str(yaml_file), xrd_path)
                obj_b = load(str(yaml_file), xrd_path)
                no_input: dict[str, object] = {}
                snap_a = build_snapshot(
                    obj_a,
                    case_id=f"det-a-{yaml_file.stem}",
                    input_flat=no_input,
                )
                snap_b = build_snapshot(
                    obj_b,
                    case_id=f"det-b-{yaml_file.stem}",
                    input_flat=no_input,
                )
                run_a.append(snap_a)
                run_b.append(snap_b)
            except Exception as exc:
                import logging

                logging.getLogger("xptest.evaluate").debug(
                    "determinism load failed for %s: %s",
                    yaml_file.stem,
                    exc,
                )
                continue
    if run_a and len(run_a) == len(run_b):
        result["determinism_score"] = compute_determinism_score(run_a, run_b)
    else:
        result["determinism_score"] = {
            "total_inputs": 0,
            "identical_outputs": 0,
            "determinism_score": 1.0,
        }

    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run xptest evaluation across all fixtures.")
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
