"""xptest CLI entry point.

Usage:
    xptest validate --composition <path> --xrd <path> [--xr <path>] [--functions <path>]
                    [--observed-resources <path>] [--config <path>] [--output <path>]

Subcommands planned:
    validate   Run Layers 1–4 against a Composition + XRD pair.
    explore    Run the Behavioral Exploration Module (Phase 5).
    drift      Run Stage 3 drift detection (Phase 4).
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import asdict, replace
from itertools import product
from pathlib import Path
from typing import Any

import yaml

from xptest.chaos.engine import (
    analyze_destructive_change,
    apply_perturbation,
    generate_perturbations,
)
from xptest.config import ConfigError, load_config
from xptest.layer4 import reporting as layer4
from xptest.loader import LoadError, load
from xptest.logic.coverage import compute_coverage, flatten_input_spec, nearby_pairs
from xptest.logic.heuristics import find_nearby_diff_heuristics, find_snapshot_heuristics
from xptest.logic.snapshot import build_snapshot
from xptest.models import Finding, Severity
from xptest.validation.facade import run_validations


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    return args.func(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xptest",
        description="Modular validation framework for Crossplane Compositions in AWS.",
    )
    sub = parser.add_subparsers(dest="subcommand")

    # --- validate ---
    val = sub.add_parser("validate", help="Run static + dependency validation (Layers 1–4).")
    val.add_argument("--composition", required=True, help="Path to Composition YAML.")
    val.add_argument("--xrd", required=True, help="Path to CompositeResourceDefinition YAML.")
    val.add_argument(
        "--xr",
        default=None,
        help=(
            "Path to XR/claim YAML used for crossplane render. "
            "When set together with --functions, xptest evaluates real go-templating output."
        ),
    )
    val.add_argument(
        "--functions",
        default=None,
        help="Path to functions.yaml used by crossplane beta render.",
    )
    val.add_argument(
        "--observed-resources",
        default=None,
        help="Optional observed-resources YAML for render-time conditional logic.",
    )
    val.add_argument(
        "--auto-xr-combinations",
        type=int,
        default=0,
        help=(
            "Auto-generate up to N XR parameter combinations from the XRD and run validation "
            "for each combination. Requires --functions and no --xr."
        ),
    )
    val.add_argument(
        "--logic-test",
        action="store_true",
        help=(
            "Run offline logic testing on rendered outputs: snapshot identity checks, "
            "coverage signatures, and nearby-input diff heuristics."
        ),
    )
    val.add_argument(
        "--auto-perturb",
        action="store_true",
        help=(
            "Generate and apply offline perturbation scenarios to detect destructive-change "
            "risks. Implies --logic-test."
        ),
    )
    val.add_argument(
        "--nearby-distance",
        type=int,
        default=1,
        help="Max input distance for nearby-diff comparisons in --logic-test mode (default: 1).",
    )
    val.add_argument(
        "--persist-snapshots",
        action="store_true",
        help="Persist logic snapshots and perturbation artifacts to disk for traceability.",
    )
    val.add_argument(
        "--snapshot-dir",
        default="xptest-artifacts",
        help="Artifact directory used with --persist-snapshots (default: xptest-artifacts).",
    )
    val.add_argument(
        "--config",
        default=None,
        help="Path to xptest.yaml config file (default: ./xptest.yaml if present).",
    )
    val.add_argument(
        "--output",
        default="findings.json",
        help="Output path for findings JSON (default: findings.json).",
    )
    val.add_argument(
        "--halt-on-critical",
        action="store_true",
        default=True,
        help="Stop pipeline on first CRITICAL finding (default: true).",
    )
    val.set_defaults(func=_cmd_validate)

    # --- drift ---
    drift = sub.add_parser("drift", help="Run Stage 3 drift detection against live AWS.")
    drift.add_argument("--composition", required=True, help="Path to Composition YAML.")
    drift.add_argument("--xrd", required=True, help="Path to CompositeResourceDefinition YAML.")
    drift.add_argument(
        "--config",
        default=None,
        help="Path to xptest.yaml config file (default: ./xptest.yaml if present).",
    )
    drift.add_argument(
        "--region",
        default=None,
        help="AWS region to query (overrides config aws_region).",
    )
    drift.add_argument(
        "--output",
        default="drift-findings.json",
        help="Output path for drift findings JSON (default: drift-findings.json).",
    )
    drift.set_defaults(func=_cmd_drift)

    # --- explore ---
    exp = sub.add_parser(
        "explore",
        help="Run Behavioral Exploration Module (input synthesis, breaking change).",
    )
    exp.add_argument("--composition", required=True, help="Path to Composition YAML.")
    exp.add_argument("--xrd", required=True, help="Path to CompositeResourceDefinition YAML.")
    exp.add_argument("--functions", required=True, help="Path to functions.yaml for render.")
    exp.add_argument(
        "--xr",
        default=None,
        help="Optional base XR YAML. If omitted, inputs are auto-generated from XRD.",
    )
    exp.add_argument(
        "--observed-resources",
        default=None,
        help="Optional observed-resources YAML for baseline renders.",
    )
    exp.add_argument(
        "--baseline",
        default=None,
        help="Path to golden baseline JSON. Overrides config baseline_path.",
    )
    exp.add_argument(
        "--max-inputs",
        type=int,
        default=0,
        help="Max pairwise inputs to generate (0 = use config default).",
    )
    exp.add_argument(
        "--coverage-threshold",
        type=float,
        default=0.0,
        help="Min branch coverage %% to pass (0 = no enforcement).",
    )
    exp.add_argument(
        "--fault-inject",
        action="store_true",
        default=True,
        help="Run fault injection sweep (default: true).",
    )
    exp.add_argument(
        "--save-baseline",
        action="store_true",
        help="Save current render results as new golden baseline.",
    )
    exp.add_argument(
        "--config",
        default=None,
        help="Path to xptest.yaml config file (default: ./xptest.yaml if present).",
    )
    exp.add_argument(
        "--output",
        default="exploration-report.json",
        help="Output path for exploration report JSON (default: exploration-report.json).",
    )
    exp.set_defaults(func=_cmd_explore)

    return parser


def _cmd_validate(args: argparse.Namespace) -> int:
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        sys.stderr.write(f"xptest: config error — {exc}\n")
        return 1

    if args.auto_xr_combinations > 0:
        if args.xr:
            sys.stderr.write("xptest: --auto-xr-combinations cannot be used together with --xr\n")
            return 1
        if not args.functions:
            sys.stderr.write("xptest: --auto-xr-combinations requires --functions\n")
            return 1
    if args.auto_perturb:
        args.logic_test = True

    if args.nearby_distance < 0:
        sys.stderr.write("xptest: --nearby-distance must be >= 0\n")
        return 1

    if args.auto_xr_combinations > 0:
        return _cmd_validate_auto_xr(args, cfg)

    try:
        obj = load(
            composition_path=args.composition,
            xrd_path=args.xrd,
            crd_bundle_path=cfg.crd_bundle_path,
            xr_path=args.xr,
            functions_path=args.functions,
            observed_resources_path=args.observed_resources,
            environment_config_paths=cfg.environment_config_paths,
        )
    except LoadError as exc:
        sys.stderr.write(f"xptest: load error — {exc}\n")
        return 1

    findings = _run_layers(obj, cfg, halt_on_critical=args.halt_on_critical)
    if not args.logic_test:
        return layer4.write(findings, output_path=args.output)

    case_id = "input-0"
    snapshots = [
        (
            case_id,
            obj,
            _load_xr_input_flat(args.xr),
        )
    ]
    logic_findings, sections = _run_logic_phase(
        snapshots,
        nearby_distance=args.nearby_distance,
        auto_perturb=args.auto_perturb,
        persist=args.persist_snapshots,
        artifact_root=args.snapshot_dir,
    )
    findings.extend(_tag_findings(logic_findings, case_id))
    sections["critical_count"] = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    return layer4.write_extended(findings, output_path=args.output, extra_sections=sections)


def _cmd_drift(args: argparse.Namespace) -> int:
    """Run Stage 3 drift detection against live AWS."""
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        sys.stderr.write(f"xptest: config error — {exc}\n")
        return 1

    # Region override from CLI takes precedence over config
    if args.region:
        cfg.aws_region = args.region

    try:
        obj = load(
            composition_path=args.composition,
            xrd_path=args.xrd,
            crd_bundle_path=cfg.crd_bundle_path,
        )
    except LoadError as exc:
        sys.stderr.write(f"xptest: load error — {exc}\n")
        return 1

    try:
        from xptest.drift import run as drift_run

        drift_findings = drift_run(obj, cfg)
    except ImportError:
        sys.stderr.write(
            "xptest: boto3 is required for drift detection. "
            "Install with: pip install xptest[drift]\n"
        )
        return 1
    except Exception as exc:
        sys.stderr.write(f"xptest: drift error — {exc}\n")
        return 1

    return layer4.write(drift_findings, output_path=args.output)


def _cmd_explore(args: argparse.Namespace) -> int:
    """Run Behavioral Exploration Module: input synthesis → render → analysis."""
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        sys.stderr.write(f"xptest: config error — {exc}\n")
        return 1

    from xptest.exploration.breaking_change import (
        detect_breaking_changes,
        load_baseline,
        save_baseline,
    )
    from xptest.exploration.fault_injection import run_fault_injection
    from xptest.exploration.input_synthesis import (
        _extract_parameters,
        _read_xrd,
        extend_suite,
        generate_seed_suite,
    )
    from xptest.exploration.invariants import (
        check_deletion_policy_escalation,
        check_minimum_resource_count,
        check_type_coverage,
        collect_baseline_deletion_policies,
        collect_declared_gvks,
        compute_baseline_min_count,
    )
    from xptest.exploration.template_coverage import measure_coverage

    max_inputs = args.max_inputs or cfg.max_exploration_inputs or 100
    baseline_path = args.baseline or cfg.baseline_path
    cov_threshold = args.coverage_threshold or cfg.coverage_threshold

    # Phase 1: Generate inputs
    if args.xr:
        # Single explicit XR — use it directly
        candidates = [("explicit-xr", None)]
        use_explicit_xr = True
    else:
        candidates = generate_seed_suite(args.xrd, max_count=max_inputs)
        use_explicit_xr = False
        if not candidates:
            sys.stderr.write("xptest: no input candidates generated from XRD\n")
            return 1

    sys.stderr.write(f"xptest explore: {len(candidates)} input(s) to render\n")

    # Phase 2: Render loop — build snapshots
    all_findings: list[Finding] = []
    snapshots: list = []
    first_obj = None

    for idx, (label, xr_doc) in enumerate(candidates):
        if use_explicit_xr:
            xr_path = args.xr
        else:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False
            ) as fh:
                yaml.safe_dump(xr_doc, fh, sort_keys=False)
                xr_path = fh.name

        try:
            obj = load(
                composition_path=args.composition,
                xrd_path=args.xrd,
                crd_bundle_path=cfg.crd_bundle_path,
                xr_path=xr_path,
                functions_path=args.functions,
                observed_resources_path=args.observed_resources,
                environment_config_paths=cfg.environment_config_paths,
            )
            if first_obj is None:
                first_obj = obj

            case_id = f"explore-{idx}:{label}" if not use_explicit_xr else "explore-0"
            input_flat = (
                flatten_input_spec(xr_doc.get("spec", {}), "spec")
                if xr_doc
                else {}
            )
            snapshot = build_snapshot(obj, case_id=case_id, input_flat=input_flat)
            snapshots.append(snapshot)

        except LoadError as exc:
            sys.stderr.write(f"xptest: render error ({label}) — {exc}\n")
            all_findings.append(Finding(
                layer=7,
                rule="explore/render-error",
                resource="",
                path="",
                severity=Severity.CRITICAL,
                message=f"Render failed for input '{label}': {exc}",
                remediation="Check composition, XRD, and functions compatibility.",
                finding_id="explore/render-error",
                category="exploration",
            ))
        finally:
            if not use_explicit_xr:
                Path(xr_path).unlink(missing_ok=True)

    if not snapshots:
        sys.stderr.write("xptest: no successful renders — cannot proceed\n")
        return layer4.write(all_findings, output_path=args.output)

    sys.stderr.write(f"xptest explore: {len(snapshots)} render(s) succeeded\n")

    # Phase 3: Breaking change detection
    if baseline_path:
        baseline = load_baseline(baseline_path)
        if baseline:
            bc_findings = detect_breaking_changes(baseline, snapshots)
            all_findings.extend(bc_findings)
            if bc_findings:
                sys.stderr.write(
                    f"xptest explore: {len(bc_findings)} breaking change(s) detected\n"
                )

    # Phase 4: Resource preservation invariants
    declared_gvks = collect_declared_gvks(snapshots)
    type_cov_findings = check_type_coverage(declared_gvks, snapshots)
    all_findings.extend(type_cov_findings)

    baseline_policies = collect_baseline_deletion_policies(snapshots)
    dp_findings = check_deletion_policy_escalation(baseline_policies, snapshots)
    all_findings.extend(dp_findings)

    min_count = compute_baseline_min_count(snapshots)
    min_count_findings = check_minimum_resource_count(min_count, snapshots)
    all_findings.extend(min_count_findings)

    # Phase 5: Fault injection
    if args.fault_inject and first_obj is not None:
        seed_xr = args.xr
        if not seed_xr and candidates:
            _, first_doc = candidates[0]
            if first_doc:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".yaml", delete=False
                ) as fh:
                    yaml.safe_dump(first_doc, fh, sort_keys=False)
                    seed_xr = fh.name

        if seed_xr:
            try:
                fi_findings, fi_snapshots = run_fault_injection(
                    first_obj,
                    composition_path=args.composition,
                    xr_path=seed_xr,
                    functions_path=args.functions,
                    environment_config_paths=cfg.environment_config_paths,
                )
                all_findings.extend(fi_findings)
                snapshots.extend(fi_snapshots)
                if fi_findings:
                    sys.stderr.write(
                        f"xptest explore: {len(fi_findings)} fault injection finding(s)\n"
                    )
            except Exception as exc:
                sys.stderr.write(f"xptest: fault injection error — {exc}\n")
            finally:
                if not args.xr and seed_xr:
                    Path(seed_xr).unlink(missing_ok=True)

    # Phase 6: Template coverage (requires Go helper)
    coverage_report = measure_coverage("", [])  # placeholder until Go helper exists

    # Phase 6b: Coverage-guided extension (extend_suite)
    if (
        not use_explicit_xr
        and coverage_report.uncovered
        and first_obj is not None
    ):
        xrd_doc = _read_xrd(args.xrd)
        xrd_spec_schema = (
            xrd_doc.get("spec", {})
            .get("versions", [{}])[0]
            .get("schema", {})
            .get("openAPIV3Schema", {})
            .get("properties", {})
            .get("spec", {})
        )
        params = _extract_parameters(xrd_spec_schema)
        uncovered_ids = [b.branch_id for b in coverage_report.uncovered]
        extensions = extend_suite(candidates, uncovered_ids, params)
        if extensions:
            sys.stderr.write(
                f"xptest explore: extending suite with {len(extensions)} "
                f"coverage-guided input(s)\n"
            )
            for idx, (label, xr_doc) in enumerate(extensions):
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".yaml", delete=False
                ) as fh:
                    yaml.safe_dump(xr_doc, fh, sort_keys=False)
                    ext_xr_path = fh.name
                try:
                    obj = load(
                        composition_path=args.composition,
                        xrd_path=args.xrd,
                        crd_bundle_path=cfg.crd_bundle_path,
                        xr_path=ext_xr_path,
                        functions_path=args.functions,
                        observed_resources_path=args.observed_resources,
                        environment_config_paths=cfg.environment_config_paths,
                    )
                    case_id = f"extend-{idx}:{label}"
                    input_flat = flatten_input_spec(xr_doc.get("spec", {}), "spec")
                    snapshot = build_snapshot(obj, case_id=case_id, input_flat=input_flat)
                    snapshots.append(snapshot)
                except LoadError as exc:
                    sys.stderr.write(
                        f"xptest: extend render error ({label}) — {exc}\n"
                    )
                finally:
                    Path(ext_xr_path).unlink(missing_ok=True)

    # Phase 7: Save baseline if requested
    if args.save_baseline and first_obj is not None:
        save_path = baseline_path or "baselines/baseline.json"
        save_baseline(snapshots, first_obj.composition_name, save_path)
        sys.stderr.write(f"xptest explore: baseline saved to {save_path}\n")

    # Build report
    report_sections: dict[str, Any] = {
        "exploration": {
            "total_inputs": len(candidates),
            "successful_renders": len([s for s in snapshots if "|" not in s.case_id]),
            "fault_injection_renders": len([s for s in snapshots if "|" in s.case_id]),
            "breaking_change_count": len(
                [f for f in all_findings if f.category == "breaking-change"]
            ),
            "invariant_count": len(
                [f for f in all_findings if f.category == "invariant"]
            ),
            "fault_injection_count": len(
                [f for f in all_findings if f.category == "fault-injection"]
            ),
            "template_coverage": {
                "total_branches": coverage_report.total_branches,
                "covered_branches": coverage_report.covered_branches,
                "coverage_pct": coverage_report.coverage_pct,
            },
        },
        "critical_count": sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
    }

    # Coverage threshold enforcement
    if cov_threshold > 0 and coverage_report.coverage_pct < cov_threshold:
        all_findings.append(Finding(
            layer=7,
            rule="explore/coverage-below-threshold",
            resource="",
            path="",
            severity=Severity.WARNING,
            message=(
                f"Branch coverage {coverage_report.coverage_pct:.1f}% "
                f"below threshold {cov_threshold:.1f}%."
            ),
            remediation="Add input combinations that exercise uncovered template branches.",
            finding_id="explore/coverage-below-threshold",
            category="exploration",
        ))

    return layer4.write_extended(
        all_findings, output_path=args.output, extra_sections=report_sections
    )


def _cmd_validate_auto_xr(args: argparse.Namespace, cfg) -> int:
    candidates = _generate_auto_xr_candidates(args.xrd, max_count=args.auto_xr_combinations)
    if not candidates:
        sys.stderr.write("xptest: failed to auto-generate XR candidates from XRD\n")
        return 1

    all_findings: list[Finding] = []
    logic_inputs: list[tuple[str, Any, dict[str, Any]]] = []
    for idx, (label, xr_doc) in enumerate(candidates):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as temp:
            yaml.safe_dump(xr_doc, temp, sort_keys=False)
            xr_path = temp.name
        case_id = f"auto-xr-{idx}:{label}"

        try:
            obj = load(
                composition_path=args.composition,
                xrd_path=args.xrd,
                crd_bundle_path=cfg.crd_bundle_path,
                xr_path=xr_path,
                functions_path=args.functions,
                observed_resources_path=args.observed_resources,
                environment_config_paths=cfg.environment_config_paths,
            )
            findings = _run_layers(obj, cfg, halt_on_critical=args.halt_on_critical)
            all_findings.extend(_tag_findings(findings, case_id))
            if args.logic_test:
                logic_inputs.append(
                    (
                        case_id,
                        obj,
                        flatten_input_spec(xr_doc.get("spec", {}), "spec"),
                    )
                )
        except LoadError as exc:
            sys.stderr.write(f"xptest: load error ({case_id}) — {exc}\n")
            all_findings.extend(
                _tag_findings(
                    [
                        replace(
                            _build_runtime_finding(str(exc)),
                            resource="",
                        )
                    ],
                    case_id,
                )
            )
        finally:
            Path(xr_path).unlink(missing_ok=True)

    if not args.logic_test:
        return layer4.write(all_findings, output_path=args.output)

    logic_findings, sections = _run_logic_phase(
        logic_inputs,
        nearby_distance=args.nearby_distance,
        auto_perturb=args.auto_perturb,
        persist=args.persist_snapshots,
        artifact_root=args.snapshot_dir,
    )
    all_findings.extend(logic_findings)
    sections["critical_count"] = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
    return layer4.write_extended(all_findings, output_path=args.output, extra_sections=sections)


def _run_layers(obj, cfg, halt_on_critical: bool) -> list:
    result = run_validations(obj, cfg, halt_on_critical=halt_on_critical)
    if result.halted_layer in {1, 2}:
        sys.stderr.write(
            f"xptest: CRITICAL finding(s) in Layer {result.halted_layer} — halting pipeline.\n"
        )
    return result.findings


def _tag_findings(findings: list, label: str) -> list:
    tagged = []
    for f in findings:
        resource = f"[{label}] {f.resource}" if f.resource else f"[{label}]"
        case_id = f.case_id or label
        tagged.append(replace(f, resource=resource, case_id=case_id))
    return tagged


def _build_runtime_finding(message: str):
    from xptest.models import Finding  # local import to avoid broad refactor

    return Finding(
        layer=1,
        rule="L1-00/auto-xr-load-error",
        resource="",
        path="",
        severity=Severity.CRITICAL,
        message=message,
        remediation="Adjust XRD defaults/options or provide an explicit --xr input.",
    )


def _generate_auto_xr_candidates(xrd_path: str, max_count: int) -> list[tuple[str, dict]]:
    with Path(xrd_path).open() as fh:
        xrd = yaml.safe_load(fh) or {}

    spec = xrd.get("spec", {})
    group = spec.get("group", "")
    versions = spec.get("versions", [])
    if not versions:
        return []
    version = versions[0].get("name", "v1alpha1")
    kind = spec.get("names", {}).get("kind", "Composite")

    schema = (
        versions[0]
        .get("schema", {})
        .get("openAPIV3Schema", {})
        .get("properties", {})
        .get("spec", {})
    )
    props: dict = schema.get("properties", {})
    required: list[str] = schema.get("required", list(props.keys())[:2])

    fields = [f for f in required if f in props]
    if not fields:
        fields = list(props.keys())[:2]

    options = [(field, _field_options(field, props.get(field, {}))) for field in fields]
    option_values = [vals for _field, vals in options]

    candidates: list[tuple[str, dict]] = []
    for idx, combo in enumerate(product(*option_values) if option_values else [()]):
        if idx >= max_count:
            break
        spec_values = {field: value for (field, _), value in zip(options, combo)}
        name = f"auto-xr-{idx}"
        xr_doc = {
            "apiVersion": f"{group}/{version}" if group else version,
            "kind": kind,
            "metadata": {
                "name": name,
                "labels": {"crossplane.io/claim-name": name},
            },
            "spec": spec_values,
        }
        label = ",".join(f"{k}={v}" for k, v in spec_values.items()) if spec_values else "default"
        candidates.append((label, xr_doc))

    return candidates


def _field_options(field_name: str, field_schema: dict) -> list:
    enum_vals = field_schema.get("enum")
    if isinstance(enum_vals, list) and enum_vals:
        return enum_vals[:2]

    field_type = field_schema.get("type", "string")
    lower = field_name.lower()

    if field_type == "boolean":
        return [True, False]
    if field_type in {"integer", "number"}:
        return [1, 2]
    if field_type == "string":
        if "namespace" in lower or lower in {"env", "environment"}:
            return ["dev", "prod"]
        if "name" in lower:
            return ["demo"]
        return ["sample"]
    if field_type == "array":
        return [[]]

    return [None]


def _run_logic_phase(
    runs: list[tuple[str, Any, dict[str, Any]]],
    nearby_distance: int,
    auto_perturb: bool,
    persist: bool,
    artifact_root: str,
) -> tuple[list[Finding], dict[str, Any]]:
    snapshots = [
        build_snapshot(obj, case_id=case_id, input_flat=input_flat)
        for case_id, obj, input_flat in runs
    ]

    findings: list[Finding] = []
    for s in snapshots:
        findings.extend(
            _tag_findings([f.to_finding() for f in find_snapshot_heuristics(s)], s.case_id)
        )

    pairs = nearby_pairs(snapshots, max_distance=nearby_distance)
    by_case = {s.case_id: s for s in snapshots}
    diff_findings = find_nearby_diff_heuristics(by_case, pairs)
    findings.extend([f.to_finding() for f in diff_findings])

    coverage_records, coverage_summary = compute_coverage(snapshots)

    perturbation_findings: list[Finding] = []
    perturbation_trace: list[dict[str, Any]] = []
    if auto_perturb:
        for baseline in snapshots:
            scenarios = generate_perturbations(baseline)
            for scenario in scenarios:
                mutated = apply_perturbation(baseline, scenario)
                destructive = analyze_destructive_change(
                    baseline,
                    mutated,
                    perturbation_id=scenario.perturbation_id,
                )
                perturbation_findings.extend([_destructive_to_finding(d) for d in destructive])
                perturbation_trace.append(
                    {
                        "baseline": baseline.case_id,
                        "mutated": mutated.case_id,
                        "perturbation_id": scenario.perturbation_id,
                        "kind": scenario.kind,
                        "params": scenario.params,
                    }
                )

    findings.extend(perturbation_findings)

    sections: dict[str, Any] = {
        "logic": {
            "coverage": asdict(coverage_summary),
            "coverage_records": [asdict(r) for r in coverage_records],
            "nearby_pairs": len(pairs),
            "logic_finding_count": len(findings) - len(perturbation_findings),
            "snapshots": [
                {
                    "case_id": s.case_id,
                    "resource_count": len(s.resources),
                    "edge_count": len(s.edges),
                    "graph_hash": s.graph_hash,
                }
                for s in snapshots
            ],
        },
        "perturbation": {
            "enabled": auto_perturb,
            "scenario_count": len(perturbation_trace),
            "finding_count": len(perturbation_findings),
            "scenarios": perturbation_trace,
        },
    }

    if persist:
        _persist_logic_artifacts(
            artifact_root=artifact_root,
            snapshots=snapshots,
            nearby=pairs,
            coverage_records=coverage_records,
            perturbation_trace=perturbation_trace,
        )

    return findings, sections


def _load_xr_input_flat(xr_path: str | None) -> dict[str, Any]:
    if not xr_path:
        return {}
    try:
        with Path(xr_path).open() as fh:
            xr_doc = yaml.safe_load(fh) or {}
        spec = xr_doc.get("spec", {})
        if isinstance(spec, dict):
            return flatten_input_spec(spec, "spec")
    except Exception:
        return {}
    return {}


def _destructive_to_finding(destructive) -> Finding:
    return Finding(
        layer=6,
        rule=destructive.finding_id,
        resource=destructive.resource_id,
        path="",
        severity=destructive.severity,
        message=f"{destructive.finding_id}: offline perturbation risk detected",
        remediation=destructive.remediation,
        finding_id=destructive.finding_id,
        category=destructive.category,
        case_id=destructive.case_id,
        baseline_case_id=destructive.baseline_case_id,
        perturbation_id=destructive.perturbation_id,
        evidence=destructive.evidence,
    )


def _persist_logic_artifacts(
    artifact_root: str,
    snapshots,
    nearby,
    coverage_records,
    perturbation_trace,
) -> None:
    base = Path(artifact_root)
    base.mkdir(parents=True, exist_ok=True)

    snapshot_dir = base / "snapshots"
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    for s in snapshots:
        payload = {
            "case_id": s.case_id,
            "input_flat": s.input_flat,
            "resources": [asdict(n) for n in s.resources],
            "edges": s.edges,
            "graph_hash": s.graph_hash,
        }
        out = snapshot_dir / f"{_safe_name(s.case_id)}.json"
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    summary = {
        "nearby_pairs": [asdict(p) for p in nearby],
        "coverage_records": [asdict(r) for r in coverage_records],
        "perturbation_trace": perturbation_trace,
    }
    (base / "logic-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _safe_name(value: str) -> str:
    return "".join(c if c.isalnum() or c in {"-", "_", "."} else "_" for c in value)


if __name__ == "__main__":
    sys.exit(main())
