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
import random
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
            "Path to XR YAML used for crossplane render. "
            "When set together with --functions, xptest evaluates real go-templating output."
        ),
    )
    val.add_argument(
        "--claim",
        default=None,
        help=(
            "Path to a namespace-scoped Claim (XRC) YAML. "
            "xptest converts it to an XR automatically using the XRD, then renders. "
            "Mutually exclusive with --xr. Useful for GitOps promotion pipelines."
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
        "--environment-configs",
        default=None,
        nargs="+",
        help="Optional EnvironmentConfig YAML file path(s) for environment-aware rendering.",
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
        "--base-xr",
        nargs="+",
        default=None,
        help=(
            "One or more known-good XR YAML files to use as base templates for mutation-based "
            "auto-XR generation. Used with --auto-xr-combinations. Each base is mutated "
            "one field at a time using valid values from the XRD schema."
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
        "--chaos-profile",
        choices=["runtime", "synthetic", "both"],
        default="runtime",
        help=(
            "Chaos scenario profile used with --auto-perturb. "
            "'runtime' targets outage-like failures (secrets/providers), "
            "'synthetic' keeps legacy graph perturbations, 'both' runs all. "
            "(default: runtime)"
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
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Stop pipeline on first CRITICAL finding (default: true).",
    )
    val.add_argument(
        "--render-mode",
        choices=["auto", "render", "offline"],
        default="auto",
        help=(
            "How to handle pipeline-mode go-templating compositions. "
            "'auto' tries crossplane render, falls back to offline. "
            "'render' requires crossplane CLI + Docker. "
            "'offline' always uses degraded static parsing. "
            "(default: auto)"
        ),
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
        "--functions",
        default=None,
        help="Path to functions.yaml for crossplane render"
        " (required for go-templating compositions).",
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
        "--claim",
        default=None,
        help=(
            "Path to a namespace-scoped Claim (XRC) YAML. "
            "Converted to XR automatically. Mutually exclusive with --xr."
        ),
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
        action=argparse.BooleanOptionalAction,
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
    exp.add_argument(
        "--render-mode",
        choices=["auto", "render", "offline"],
        default="auto",
        help="Rendering mode for go-templating compositions (default: auto).",
    )
    exp.set_defaults(func=_cmd_explore)

    # --- scan ---
    scan = sub.add_parser(
        "scan",
        help="Scan a package directory for all Compositions and validate each.",
    )
    scan.add_argument(
        "root",
        help="Root directory to scan recursively for Compositions and XRDs.",
    )
    scan.add_argument(
        "--functions",
        default=None,
        help="Path to functions.yaml for render mode (optional, auto-detected).",
    )
    scan.add_argument(
        "--claims-dir",
        default=None,
        help=(
            "Directory containing Claim (XRC) YAML files. "
            "Each claim is matched to its composition via the XRD and converted to an XR "
            "for rendering. Useful for scanning a GitOps promotion repo."
        ),
    )
    scan.add_argument(
        "--config",
        default=None,
        help="Path to xptest.yaml config file.",
    )
    scan.add_argument(
        "--output",
        default="scan-report.json",
        help="Output path for scan report JSON (default: scan-report.json).",
    )
    scan.add_argument(
        "--halt-on-critical",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Stop pipeline on first CRITICAL finding per composition.",
    )
    scan.add_argument(
        "--render-mode",
        choices=["auto", "render", "offline"],
        default="auto",
        help="Rendering mode for go-templating compositions (default: auto).",
    )
    scan.set_defaults(func=_cmd_scan)

    return parser


def _cmd_validate(args: argparse.Namespace) -> int:
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        sys.stderr.write(f"xptest: config error — {exc}\n")
        return 1

    if args.claim and args.xr:
        sys.stderr.write("xptest: --claim and --xr are mutually exclusive\n")
        return 1

    try:
        args.composition = _resolve_input_path(args.composition)
        args.xrd = _resolve_input_path(args.xrd)
        if args.xr:
            args.xr = _resolve_input_path(args.xr)
        if args.claim:
            args.claim = _resolve_input_path(args.claim)
        if args.functions:
            args.functions = _resolve_input_path(args.functions)
        if args.observed_resources:
            args.observed_resources = _resolve_input_path(args.observed_resources)
        if args.environment_configs:
            args.environment_configs = [
                _resolve_input_path(path) for path in args.environment_configs
            ]
        if args.base_xr:
            args.base_xr = [_resolve_input_path(path) for path in args.base_xr]
    except (FileNotFoundError, ValueError) as exc:
        sys.stderr.write(f"xptest: path resolution error — {exc}\n")
        return 1

    # Convert claim to XR if --claim was provided
    if args.claim:
        args.xr = _convert_claim_to_xr_file(args.claim, args.xrd, args.composition)
        if args.xr is None:
            return 1

    if args.base_xr and args.auto_xr_combinations <= 0:
        sys.stderr.write("xptest: --base-xr requires --auto-xr-combinations\n")
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
        if not args.base_xr:
            discovered = _discover_base_xrs(args.composition)
            if discovered:
                args.base_xr = discovered
        return _cmd_validate_auto_xr(args, cfg)

    # Merge CLI environment-configs with config file ones
    env_config_paths = cfg.environment_config_paths
    if args.environment_configs:
        env_config_paths = list(args.environment_configs) + env_config_paths

    try:
        obj = load(
            composition_path=args.composition,
            xrd_path=args.xrd,
            crd_bundle_path=cfg.crd_bundle_path,
            xr_path=args.xr,
            functions_path=args.functions,
            observed_resources_path=args.observed_resources,
            environment_config_paths=env_config_paths,
            render_mode=args.render_mode,
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
        chaos_profile=args.chaos_profile,
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
            functions_path=args.functions,
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
    import time as _time

    from xptest import progress

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
    from xptest.exploration.determinism import compute_determinism_score
    from xptest.exploration.fault_injection import (
        compute_mutation_score,
        run_fault_injection,
    )
    from xptest.exploration.input_synthesis import (
        _extract_parameters,
        _read_xrd,
        compute_tway_coverage,
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

    if getattr(args, "claim", None) and args.xr:
        sys.stderr.write("xptest: --claim and --xr are mutually exclusive\n")
        return 1

    # Convert claim → XR if provided
    if getattr(args, "claim", None):
        args.claim = _resolve_input_path(args.claim)
        args.xr = _convert_claim_to_xr_file(args.claim, args.xrd, args.composition)
        if args.xr is None:
            return 1

    progress.init()
    render_mode = getattr(args, "render_mode", "auto")

    # Early availability check: when render_mode is "auto" and crossplane
    # CLI is not on PATH, fall back to offline immediately instead of
    # timing out on the first render attempt.
    if render_mode == "auto":
        from xptest.render import crossplane_cli_available

        if not crossplane_cli_available():
            progress.step("crossplane CLI not found — falling back to offline mode")
            render_mode = "offline"

    max_inputs = args.max_inputs or cfg.max_exploration_inputs or 100
    baseline_path = args.baseline or cfg.baseline_path
    cov_threshold = args.coverage_threshold or cfg.coverage_threshold

    # Phase 1: Generate inputs
    progress.phase("Input synthesis")
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

    progress.step(f"{len(candidates)} input(s) to render")

    # Phase 2: Render loop — build snapshots
    progress.phase(f"Rendering {len(candidates)} input(s)")
    t0_render = _time.monotonic()
    all_findings: list[Finding] = []
    snapshots: list = []
    first_obj = None

    for idx, (label, xr_doc) in enumerate(candidates):
        progress.combo(idx, len(candidates), label)
        if use_explicit_xr:
            xr_path = args.xr
        else:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
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
                render_mode=render_mode,
            )
            if first_obj is None:
                first_obj = obj

            case_id = f"explore-{idx}:{label}" if not use_explicit_xr else "explore-0"
            input_flat = flatten_input_spec(xr_doc.get("spec", {}), "spec") if xr_doc else {}
            snapshot = build_snapshot(obj, case_id=case_id, input_flat=input_flat)
            snapshots.append(snapshot)

        except LoadError as exc:
            progress.warn(f"render error ({label}): {exc}")
            all_findings.append(
                Finding(
                    layer=7,
                    rule="explore/render-error",
                    resource="",
                    path="",
                    severity=Severity.CRITICAL,
                    message=f"Render failed for input '{label}': {exc}",
                    remediation="Check composition, XRD, and functions compatibility.",
                    finding_id="explore/render-error",
                    category="exploration",
                )
            )
        finally:
            if not use_explicit_xr:
                Path(xr_path).unlink(missing_ok=True)

    t_render = _time.monotonic() - t0_render
    if not snapshots:
        progress.warn("no successful renders — cannot proceed")
        return layer4.write(all_findings, output_path=args.output)

    progress.done(f"{len(snapshots)} render(s) succeeded in {t_render:.2f}s")

    # Phase 3: Breaking change detection
    progress.phase("Analysis")
    if baseline_path:
        baseline = load_baseline(baseline_path)
        if baseline:
            bc_findings = detect_breaking_changes(baseline, snapshots)
            all_findings.extend(bc_findings)
            if bc_findings:
                progress.step(f"{len(bc_findings)} breaking change(s) detected")

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
    inv_count = len(type_cov_findings) + len(dp_findings) + len(min_count_findings)
    progress.step(f"Invariant checks: {inv_count} findings")

    # Phase 5: Fault injection
    fi_findings: list[Finding] = []
    fault_sweep_count = 0
    if args.fault_inject and first_obj is not None:
        progress.phase("Fault injection")
        from xptest.exploration.fault_injection import build_fault_sweep_order

        fault_sweep_count = len(build_fault_sweep_order(first_obj))
        progress.step(f"{fault_sweep_count} fault target(s)")
        seed_xr = args.xr
        if not seed_xr and candidates:
            _, first_doc = candidates[0]
            if first_doc:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
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
                    render_mode=render_mode,
                )
                all_findings.extend(fi_findings)
                snapshots.extend(fi_snapshots)
                progress.step(f"{len(fi_findings)} fault injection finding(s)")
            except Exception as exc:
                progress.warn(f"fault injection error: {exc}")
            finally:
                if not args.xr and seed_xr:
                    Path(seed_xr).unlink(missing_ok=True)

    # Phase 6: Template coverage (requires Go helper)
    coverage_report = measure_coverage("", [])  # placeholder until Go helper exists

    # Phase 6b: Coverage-guided extension (extend_suite)
    if not use_explicit_xr and coverage_report.uncovered and first_obj is not None:
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
                f"xptest explore: extending suite with {len(extensions)} coverage-guided input(s)\n"
            )
            for idx, (label, xr_doc) in enumerate(extensions):
                with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
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
                        render_mode=render_mode,
                    )
                    case_id = f"extend-{idx}:{label}"
                    input_flat = flatten_input_spec(xr_doc.get("spec", {}), "spec")
                    snapshot = build_snapshot(obj, case_id=case_id, input_flat=input_flat)
                    snapshots.append(snapshot)
                except LoadError as exc:
                    progress.warn(f"extend render error ({label}): {exc}")
                finally:
                    Path(ext_xr_path).unlink(missing_ok=True)

    # Phase 7: Compute §3.3.4 metrics
    # t-way coverage
    tway_report: dict[str, Any] = {
        "t": 2,
        "total_tuples": 0,
        "covered_tuples": 0,
        "coverage_pct": 100.0,
    }
    if not use_explicit_xr:
        xrd_doc_m = _read_xrd(args.xrd)
        xrd_spec_m = (
            xrd_doc_m.get("spec", {})
            .get("versions", [{}])[0]
            .get("schema", {})
            .get("openAPIV3Schema", {})
            .get("properties", {})
            .get("spec", {})
        )
        params_m = _extract_parameters(xrd_spec_m)
        if params_m:
            tway_report = compute_tway_coverage(candidates, params_m, t=2)

    # Mutation score
    mutation_report = compute_mutation_score(fault_sweep_count, fi_findings)

    # Determinism score — re-render first few inputs and compare
    progress.phase("Determinism check")
    determinism_report: dict[str, Any] = {
        "total_inputs": 0,
        "identical_outputs": 0,
        "determinism_score": 1.0,
    }
    det_limit = min(5, len(candidates))
    if det_limit > 0 and not use_explicit_xr:
        progress.step(f"Re-rendering {det_limit} input(s) for determinism")
        run_b_snapshots: list = []
        for idx in range(det_limit):
            label, xr_doc = candidates[idx]
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as fh:
                yaml.safe_dump(xr_doc, fh, sort_keys=False)
                det_xr_path = fh.name
            try:
                det_obj = load(
                    composition_path=args.composition,
                    xrd_path=args.xrd,
                    crd_bundle_path=cfg.crd_bundle_path,
                    xr_path=det_xr_path,
                    functions_path=args.functions,
                    observed_resources_path=args.observed_resources,
                    environment_config_paths=cfg.environment_config_paths,
                    render_mode=render_mode,
                )
                det_case = f"det-{idx}:{label}"
                det_flat = flatten_input_spec(xr_doc.get("spec", {}), "spec")
                det_snap = build_snapshot(det_obj, case_id=det_case, input_flat=det_flat)
                run_b_snapshots.append(det_snap)
            except LoadError:
                pass
            finally:
                Path(det_xr_path).unlink(missing_ok=True)

        # Compare run_b against the first N snapshots from run_a
        run_a_subset = [s for s in snapshots if "fault|" not in s.case_id][:det_limit]
        if len(run_a_subset) == len(run_b_snapshots):
            determinism_report = compute_determinism_score(run_a_subset, run_b_snapshots)

    # Phase 8: Save baseline if requested
    if args.save_baseline and first_obj is not None:
        save_path = baseline_path or "baselines/baseline.json"
        save_baseline(snapshots, first_obj.composition_name, save_path)
        progress.step(f"Baseline saved to {save_path}")

    # Build report
    report_sections: dict[str, Any] = {
        "exploration": {
            "total_inputs": len(candidates),
            "successful_renders": len([s for s in snapshots if "|" not in s.case_id]),
            "fault_injection_renders": len([s for s in snapshots if "|" in s.case_id]),
            "breaking_change_count": len(
                [f for f in all_findings if f.category == "breaking-change"]
            ),
            "invariant_count": len([f for f in all_findings if f.category == "invariant"]),
            "fault_injection_count": len(
                [f for f in all_findings if f.category == "fault-injection"]
            ),
            "template_coverage": {
                "total_branches": coverage_report.total_branches,
                "covered_branches": coverage_report.covered_branches,
                "coverage_pct": coverage_report.coverage_pct,
            },
            "tway_coverage": tway_report,
            "mutation_score": mutation_report,
            "determinism_score": determinism_report,
        },
        "critical_count": sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
    }

    # Coverage threshold enforcement
    if cov_threshold > 0 and coverage_report.coverage_pct < cov_threshold:
        all_findings.append(
            Finding(
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
            )
        )

    return layer4.write_extended(
        all_findings, output_path=args.output, extra_sections=report_sections
    )


def _cmd_validate_auto_xr(args: argparse.Namespace, cfg) -> int:
    import time as _time

    from xptest import progress

    progress.init()

    # Early availability check: fall back to offline when crossplane CLI
    # is absent so we don't pay a subprocess timeout per combination.
    if args.render_mode == "auto":
        from xptest.render import crossplane_cli_available

        if not crossplane_cli_available():
            progress.step("crossplane CLI not found — falling back to offline mode")
            args.render_mode = "offline"

    progress.phase("Generating XR parameter combinations")

    candidates = _generate_auto_xr_candidates(
        args.xrd,
        max_count=args.auto_xr_combinations,
        base_xr_paths=args.base_xr,
    )
    if not candidates:
        sys.stderr.write("xptest: failed to auto-generate XR candidates from XRD\n")
        return 1

    # Deduplicate candidates that produce identical spec values
    seen_specs: set[str] = set()
    unique_candidates: list[tuple[str, dict]] = []
    for label, xr_doc in candidates:
        spec_key = json.dumps(xr_doc.get("spec", {}), sort_keys=True)
        if spec_key not in seen_specs:
            seen_specs.add(spec_key)
            unique_candidates.append((label, xr_doc))
    skipped = len(candidates) - len(unique_candidates)
    candidates = unique_candidates
    progress.step(
        f"{len(candidates)} unique combinations"
        + (f" ({skipped} duplicates removed)" if skipped else "")
    )

    # Merge CLI environment-configs with config file ones
    env_config_paths = cfg.environment_config_paths
    if args.environment_configs:
        env_config_paths = list(args.environment_configs) + env_config_paths

    # --- Optimisation: parse composition and XRD once ---
    progress.phase("Loading composition and XRD")
    comp_doc = yaml.safe_load(Path(args.composition).read_text())
    xrd_doc = yaml.safe_load(Path(args.xrd).read_text())
    progress.step("Parsed composition and XRD from disk (once)")

    # --- Optimisation: pre-load CRD cache once ---
    from xptest.cache import load_crd_bundle

    crd_cache = load_crd_bundle(cfg.crd_bundle_path)

    # --- Render + validate loop ---
    progress.phase(f"Rendering and validating {len(candidates)} combinations")
    timings: dict[str, float] = {"render": 0.0, "validate": 0.0, "snapshot": 0.0}

    all_findings: list[Finding] = []
    logic_inputs: list[tuple[str, Any, dict[str, Any]]] = []
    for idx, (label, xr_doc) in enumerate(candidates):
        progress.combo(idx, len(candidates), label)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as temp:
            yaml.safe_dump(xr_doc, temp, sort_keys=False)
            xr_path = temp.name
        case_id = f"auto-xr-{idx}:{label}"

        try:
            t0 = _time.monotonic()
            obj = load(
                composition_path=args.composition,
                xrd_path=args.xrd,
                crd_bundle_path=cfg.crd_bundle_path,
                xr_path=xr_path,
                functions_path=args.functions,
                observed_resources_path=args.observed_resources,
                environment_config_paths=env_config_paths,
                render_mode=args.render_mode,
                _comp_doc=comp_doc,
                _xrd_doc=xrd_doc,
            )
            timings["render"] += _time.monotonic() - t0

            t0 = _time.monotonic()
            findings = _run_layers(
                obj, cfg, halt_on_critical=args.halt_on_critical, crd_cache=crd_cache
            )
            timings["validate"] += _time.monotonic() - t0

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
            progress.warn(f"load error ({case_id}): {exc}")
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

    progress.done(
        f"Render+validate: render={timings['render']:.1f}s validate={timings['validate']:.1f}s"
    )

    if not args.logic_test:
        return layer4.write(all_findings, output_path=args.output)

    logic_findings, sections = _run_logic_phase(
        logic_inputs,
        nearby_distance=args.nearby_distance,
        auto_perturb=args.auto_perturb,
        chaos_profile=args.chaos_profile,
        persist=args.persist_snapshots,
        artifact_root=args.snapshot_dir,
    )
    all_findings.extend(logic_findings)
    sections["critical_count"] = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
    sections["timings"] = timings
    return layer4.write_extended(all_findings, output_path=args.output, extra_sections=sections)


def _run_layers(obj, cfg, halt_on_critical: bool, crd_cache=None) -> list:
    result = run_validations(
        obj,
        cfg,
        halt_on_critical=halt_on_critical,
        crd_cache=crd_cache,
    )
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


def _discover_base_xrs(composition_path: str) -> list[str]:
    """Discover existing composition-test XR files for a given composition path."""
    comp = Path(composition_path).resolve()
    parts = comp.parts
    try:
        pkg_idx = parts.index("pkg")
    except ValueError:
        return []
    repo_root = Path(*parts[:pkg_idx]) if pkg_idx > 1 else Path(parts[0])
    relative = Path(*parts[pkg_idx + 1 :]).parent  # e.g. community/ec2-instance
    resources_dir = repo_root / "composition-tests" / relative / "resources"
    if not resources_dir.is_dir():
        return []
    found = sorted(
        str(p) for p in resources_dir.glob("xr-*.yaml") if "bad" not in p.name
    )
    if found:
        sys.stderr.write(
            f"xptest: auto-discovered {len(found)} base XR(s) from composition-tests\n"
        )
    return found


def _generate_auto_xr_candidates(
    xrd_path: str,
    max_count: int,
    base_xr_paths: list[str] | None = None,
) -> list[tuple[str, dict]]:
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

    if base_xr_paths:
        return _generate_mutation_candidates(
            base_xr_paths,
            schema,
            max_count,
        )

    # Fallback: synthesis-based generation (original behaviour)
    params = _extract_flat_params("", schema)
    if not params:
        return []

    combos = _pairwise_cover_params(params, max_count)

    candidates: list[tuple[str, dict]] = []
    for idx, flat_combo in enumerate(combos):
        spec_values = _unflatten(flat_combo)
        name = f"auto-xr-{idx}"

        claim_namespace = "default"
        for key, value in flat_combo.items():
            if "namespace" in key.lower() and isinstance(value, str):
                claim_namespace = value
                break

        xr_doc = {
            "apiVersion": f"{group}/{version}" if group else version,
            "kind": kind,
            "metadata": {
                "name": name,
                "labels": {
                    "crossplane.io/claim-name": name,
                    "crossplane.io/claim-namespace": claim_namespace,
                },
            },
            "spec": spec_values,
        }
        label = ",".join(f"{k}={v}" for k, v in flat_combo.items()) if flat_combo else "default"
        candidates.append((label, xr_doc))

    return candidates


def _generate_mutation_candidates(
    base_xr_paths: list[str],
    spec_schema: dict,
    max_count: int,
) -> list[tuple[str, dict]]:
    """Generate XR candidates by mutating known-good base XRs one field at a time.

    For each base XR, identify mutable fields (enums, booleans, bounded integers)
    from the XRD schema, then produce variants by changing one field to each of its
    other valid values. Finally, add pairwise multi-field mutations if budget remains.
    """
    import copy

    # Load base XR documents (skip files with 'bad' in the name)
    bases: list[tuple[str, dict]] = []
    for path_str in base_xr_paths:
        p = Path(path_str)
        if "bad" in p.name.lower():
            continue
        try:
            with p.open() as fh:
                doc = yaml.safe_load(fh)
            if isinstance(doc, dict) and "spec" in doc:
                bases.append((p.stem, doc))
        except Exception:
            sys.stderr.write(f"xptest: warning — could not load base XR: {path_str}\n")

    if not bases:
        return []

    # Extract mutable fields from schema
    params = _extract_flat_params("", spec_schema)
    if not params:
        # No mutable fields found — return bases as-is
        return [(name, doc) for name, doc in bases]

    # For mutation-based generation, only keep fields with real domain values
    # (enums, booleans, bounded integers). Exclude synthetic placeholders and
    # object-type combos (dicts) which are too complex to mutate safely.
    _synthetic = {"sample-a", "sample-b", "demo", "test-resource", "value-1"}
    params = [
        (path, domain)
        for path, domain in params
        if not any(isinstance(v, dict) for v in domain)
        and not all(str(v) in _synthetic for v in domain)
    ]

    candidates: list[tuple[str, dict]] = []

    # Phase 1: Include each base XR as-is
    for base_name, base_doc in bases:
        candidates.append((f"base:{base_name}", copy.deepcopy(base_doc)))

    # Phase 2: Single-field mutations from each base
    for base_name, base_doc in bases:
        base_spec = base_doc.get("spec", {})
        base_flat = _flatten_spec(base_spec)

        for field_path, domain in params:
            current_val = base_flat.get(field_path)
            for alt_val in domain:
                if alt_val == current_val:
                    continue
                mutated = copy.deepcopy(base_doc)
                _set_nested(mutated["spec"], field_path, alt_val)
                label = f"mutate:{base_name}:{field_path}={alt_val}"
                candidates.append((label, mutated))
                if len(candidates) >= max_count:
                    return candidates

    # Phase 3: Pairwise two-field mutations if budget remains
    if len(candidates) < max_count and len(params) >= 2:
        for base_name, base_doc in bases:
            base_spec = base_doc.get("spec", {})
            base_flat = _flatten_spec(base_spec)

            for i, (field_a, domain_a) in enumerate(params):
                for field_b, domain_b in params[i + 1 :]:
                    cur_a = base_flat.get(field_a)
                    cur_b = base_flat.get(field_b)
                    for val_a in domain_a:
                        if val_a == cur_a:
                            continue
                        for val_b in domain_b:
                            if val_b == cur_b:
                                continue
                            mutated = copy.deepcopy(base_doc)
                            _set_nested(mutated["spec"], field_a, val_a)
                            _set_nested(mutated["spec"], field_b, val_b)
                            label = f"pair:{base_name}:{field_a}={val_a},{field_b}={val_b}"
                            candidates.append((label, mutated))
                            if len(candidates) >= max_count:
                                return candidates

    return candidates


def _flatten_spec(spec: dict, prefix: str = "") -> dict[str, Any]:
    """Flatten a nested spec dict into dotted-path keys."""
    result: dict[str, Any] = {}
    for key, value in spec.items():
        dotted = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            result.update(_flatten_spec(value, dotted))
        else:
            result[dotted] = value
    return result


def _set_nested(target: dict, dotted_path: str, value: Any) -> None:
    """Set a value in a nested dict using a dotted path, creating intermediates as needed."""
    parts = dotted_path.split(".")
    for part in parts[:-1]:
        if part not in target or not isinstance(target[part], dict):
            target[part] = {}
        target = target[part]
    target[parts[-1]] = value


def _extract_flat_params(
    prefix: str,
    schema: dict,
    *,
    _depth: int = 0,
) -> list[tuple[str, list]]:
    """Recursively extract (dotted_path, domain_values) from a schema.

    For object types, recurse into sub-fields instead of generating object combos.
    Includes required fields first, then optional fields that have enums, booleans,
    or bounded integers (i.e. fields that contribute meaningful variation).
    """
    props: dict = dict(schema.get("properties", {}))
    required: list[str] = list(schema.get("required", []))

    # Merge allOf / oneOf constraints
    for constraint in schema.get("allOf", []):
        for k, v in constraint.get("properties", {}).items():
            if not isinstance(v, dict):
                continue
            if k in props and isinstance(props[k], dict):
                # Enrich existing property with constraint keys (enum, pattern, etc.)
                for attr in ("enum", "pattern", "minimum", "maximum"):
                    if attr in v and attr not in props[k]:
                        props[k][attr] = v[attr]
            else:
                props[k] = v
        required.extend(constraint.get("required", []))
    for constraint in schema.get("oneOf", []):
        for k, v in constraint.get("properties", {}).items():
            if not isinstance(v, dict):
                continue
            if k in props and isinstance(props[k], dict):
                for attr in ("enum", "pattern", "minimum", "maximum"):
                    if attr in v and attr not in props[k]:
                        props[k][attr] = v[attr]
            else:
                props[k] = v
        required.extend(constraint.get("required", []))

    required = list(dict.fromkeys(required))

    # Order: required first, then optional fields that add variation
    ordered: list[str] = [f for f in required if f in props]
    for name in props:
        if name not in ordered and _has_variation(props[name]):
            ordered.append(name)

    params: list[tuple[str, list]] = []
    for name in ordered:
        field_schema = props[name]
        dotted = f"{prefix}.{name}" if prefix else name
        field_type = field_schema.get("type", "string")

        if field_type == "object" and _depth < 3:
            sub = _extract_flat_params(dotted, field_schema, _depth=_depth + 1)
            if sub:
                params.extend(sub)
                continue

        if field_type == "array" and field_schema.get("items", {}).get("type") == "object":
            domain = _field_options(name, field_schema)
            if domain:
                params.append((dotted, domain))
            continue

        domain = _field_options(name, field_schema)
        if domain:
            params.append((dotted, domain))

    return params


def _has_variation(field_schema: dict) -> bool:
    """Return True if a field contributes more than one value to combinations."""
    if field_schema.get("enum"):
        return True
    ft = field_schema.get("type", "string")
    if ft == "boolean":
        return True
    if ft == "string":
        return True
    if ft in {"integer", "number"} and (
        field_schema.get("minimum") is not None or field_schema.get("maximum") is not None
    ):
        return True
    if ft == "object":
        return bool(field_schema.get("properties") or field_schema.get("allOf"))
    return False


def _pairwise_cover_params(
    params: list[tuple[str, list]],
    max_count: int,
) -> list[dict[str, object]]:
    """Generate pairwise covering array. Uses allpairspy if available."""
    if not params:
        return []
    names = [n for n, _ in params]
    domains = [d for _, d in params]

    # AllPairs requires >= 2 parameters; for 1 param just enumerate values
    if len(params) < 2:
        return [{names[0]: v} for v in domains[0][:max_count]]

    try:
        from allpairspy import AllPairs

        combos: list[dict[str, object]] = []
        for row in AllPairs(domains):
            if len(combos) >= max_count:
                break
            combos.append(dict(zip(names, row)))
    except ImportError:
        combos = _greedy_pairwise(names, domains, max_count)

    # Fill remaining slots with random combinations (deterministic seed)
    if len(combos) < max_count:
        rng = random.Random(42)
        existing = {json.dumps(c, sort_keys=True, default=str) for c in combos}
        attempts = 0
        while len(combos) < max_count and attempts < max_count * 10:
            row = {n: rng.choice(d) for n, d in zip(names, domains)}
            key = json.dumps(row, sort_keys=True, default=str)
            if key not in existing:
                existing.add(key)
                combos.append(row)
            attempts += 1

    return combos


def _greedy_pairwise(
    names: list[str],
    domains: list[list],
    max_count: int,
) -> list[dict[str, object]]:
    """Greedy pairwise fallback when allpairspy is unavailable."""
    n = len(names)
    if n == 0:
        return []
    if n == 1:
        return [{names[0]: v} for v in domains[0][:max_count]]

    # Build uncovered pair set
    uncovered: set[tuple[int, int, int, int]] = set()
    for i in range(n):
        for j in range(i + 1, n):
            for vi_idx, _ in enumerate(domains[i]):
                for vj_idx, _ in enumerate(domains[j]):
                    uncovered.add((i, vi_idx, j, vj_idx))

    combos: list[dict[str, object]] = []
    while uncovered and len(combos) < max_count:
        best_row: list | None = None
        best_score = 0

        for pair in list(uncovered)[:80]:
            i, vi_idx, j, vj_idx = pair
            row = [d[0] for d in domains]
            row[i] = domains[i][vi_idx]
            row[j] = domains[j][vj_idx]
            score = sum(
                1
                for (pi, pvi, pj, pvj) in uncovered
                if row[pi] == domains[pi][pvi] and row[pj] == domains[pj][pvj]
            )
            if score > best_score:
                best_score = score
                best_row = row

        if best_row is None:
            break

        combos.append(dict(zip(names, best_row)))
        for i in range(n):
            for j in range(i + 1, n):
                for vi_idx, v in enumerate(domains[i]):
                    if best_row[i] != v:
                        continue
                    for vj_idx, v2 in enumerate(domains[j]):
                        if best_row[j] == v2:
                            uncovered.discard((i, vi_idx, j, vj_idx))

    return combos


def _unflatten(flat: dict[str, object]) -> dict:
    """Convert dotted-path keys back to nested dicts."""
    result: dict = {}
    for dotted_key, value in flat.items():
        parts = dotted_key.split(".")
        target = result
        for part in parts[:-1]:
            next_level = target.get(part)
            if not isinstance(next_level, dict):
                # Collision: intermediate is a leaf or missing — overwrite with dict
                target[part] = {}
            target = target[part]
        target[parts[-1]] = value
    return result


def _field_options(field_name: str, field_schema: dict) -> list:
    enum_vals = field_schema.get("enum")
    if isinstance(enum_vals, list) and enum_vals:
        return enum_vals

    field_type = field_schema.get("type", "string")
    lower = field_name.lower()

    if field_type == "boolean":
        return [True, False]
    if field_type in {"integer", "number"}:
        minimum = field_schema.get("minimum", 1)
        maximum = field_schema.get("maximum", 100)
        values = sorted({minimum, maximum})
        mid = (minimum + maximum) // 2
        if mid not in values:
            values = sorted({minimum, mid, maximum})
        return values
    if field_type == "object":
        # When called directly (not via _extract_flat_params), generate
        # a few combos from sub-fields for backward compatibility.
        props = dict(field_schema.get("properties", {}))
        required = list(field_schema.get("required", []))
        for constraint in field_schema.get("allOf", []):
            for k, v in constraint.get("properties", {}).items():
                if not isinstance(v, dict):
                    continue
                if k in props and isinstance(props[k], dict):
                    for attr in ("enum", "pattern", "minimum", "maximum"):
                        if attr in v and attr not in props[k]:
                            props[k][attr] = v[attr]
                else:
                    props[k] = v
            required.extend(constraint.get("required", []))
        for constraint in field_schema.get("oneOf", []):
            for k, v in constraint.get("properties", {}).items():
                if not isinstance(v, dict):
                    continue
                if k in props and isinstance(props[k], dict):
                    for attr in ("enum", "pattern", "minimum", "maximum"):
                        if attr in v and attr not in props[k]:
                            props[k][attr] = v[attr]
                else:
                    props[k] = v
            required.extend(constraint.get("required", []))
        required = [f for f in dict.fromkeys(required) if f in props]
        fields = required if required else list(props.keys())[:3]
        if not fields:
            return [{}]
        option_sets: list[tuple[str, list]] = []
        for f in fields:
            vals = _field_options(f, props.get(f, {}))
            if vals:
                option_sets.append((f, vals))
        if not option_sets:
            return [{}]
        combos: list[dict[str, object]] = []
        for idx, combo in enumerate(product(*(vals for _f, vals in option_sets))):
            if idx >= 8:
                break
            obj = {field: value for (field, _vals), value in zip(option_sets, combo)}
            combos.append(obj)
        return combos or [{}]
    if field_type == "string":
        # Pattern-constrained strings without enum values cannot be safely mutated
        if field_schema.get("pattern"):
            return []
        if "namespace" in lower or lower in {"env", "environment"}:
            return ["dev", "prod"]
        if "region" in lower:
            return ["us-east-1", "eu-west-1"]
        if "name" in lower:
            return ["demo", "test-resource"]
        return ["sample-a", "sample-b"]
    if field_type == "array":
        items = field_schema.get("items", {})
        if items.get("type") == "object":
            obj_variants = _field_options(field_name, items)
            if obj_variants and isinstance(obj_variants[0], dict):
                result = [[]]
                result.append([obj_variants[0]])
                if len(obj_variants) > 1:
                    result.append([obj_variants[0], obj_variants[1]])
                return result
        return [[], ["value-1"]]

    return [None]


def _run_logic_phase(
    runs: list[tuple[str, Any, dict[str, Any]]],
    nearby_distance: int,
    auto_perturb: bool,
    chaos_profile: str,
    persist: bool,
    artifact_root: str,
) -> tuple[list[Finding], dict[str, Any]]:
    import time as _time

    from xptest import progress
    from xptest.chaos.criticality import classify_criticality

    progress.phase("Logic testing")
    t0_logic = _time.monotonic()

    # --- Build snapshots ---
    t0 = _time.monotonic()
    snapshots = [
        build_snapshot(obj, case_id=case_id, input_flat=input_flat)
        for case_id, obj, input_flat in runs
    ]
    t_snapshot = _time.monotonic() - t0
    progress.step(f"Built {len(snapshots)} snapshots ({t_snapshot:.2f}s)")

    # --- Snapshot heuristics ---
    findings: list[Finding] = []
    for s in snapshots:
        findings.extend(
            _tag_findings([f.to_finding() for f in find_snapshot_heuristics(s)], s.case_id)
        )

    # --- Nearby pairs ---
    pairs = nearby_pairs(snapshots, max_distance=nearby_distance)
    by_case = {s.case_id: s for s in snapshots}
    diff_findings = find_nearby_diff_heuristics(by_case, pairs)
    findings.extend([f.to_finding() for f in diff_findings])
    progress.step(f"Nearby pairs: {len(pairs)}, diff findings: {len(diff_findings)}")

    # --- Coverage ---
    coverage_records, coverage_summary = compute_coverage(snapshots)
    progress.step(
        f"Coverage: {coverage_summary.unique_graphs} unique graphs, "
        f"{coverage_summary.unique_presence_signatures} presence sigs"
    )

    # --- Perturbation ---
    perturbation_findings: list[Finding] = []
    perturbation_trace: list[dict[str, Any]] = []
    perturbation_stats: dict[str, Any] = {
        "dedup_skipped": 0,
        "total_scenarios": 0,
        "unique_baselines": 0,
        "scenario_timings": [],
    }

    if auto_perturb:
        progress.phase("Chaos perturbation testing")
        t0_perturb = _time.monotonic()

        # Deduplicate baselines by structural identity (resource presence + edges),
        # not full graph hash. Field-level differences should not duplicate
        # chaos scenarios when structure is identical.
        seen_keys: dict[str, str] = {}  # structure_key -> first case_id
        dedup_baselines: list = []
        dedup_skipped = 0
        for s in snapshots:
            key = _chaos_structure_key(s)
            if key not in seen_keys:
                seen_keys[key] = s.case_id
                dedup_baselines.append(s)
            else:
                dedup_skipped += 1
        perturbation_stats["dedup_skipped"] = dedup_skipped
        perturbation_stats["unique_baselines"] = len(dedup_baselines)
        if dedup_skipped:
            progress.step(
                f"Dedup: {len(dedup_baselines)} unique baselines "
                f"({dedup_skipped} identical structures skipped)"
            )

        # Optimisation: cache criticality classification per baseline
        criticality_cache: dict[str, dict] = {}

        total_scenarios = 0
        for baseline in dedup_baselines:
            scenarios = generate_perturbations(baseline, profile=chaos_profile)
            total_scenarios += len(scenarios)

        perturbation_stats["total_scenarios"] = total_scenarios
        progress.step(
            f"Running {total_scenarios} scenarios across {len(dedup_baselines)} baselines"
        )

        scenario_counter = 0
        for baseline in dedup_baselines:
            # Cache criticality
            baseline_key = _chaos_structure_key(baseline)
            if baseline_key not in criticality_cache:
                criticality_cache[baseline_key] = classify_criticality(baseline)

            scenarios = generate_perturbations(baseline, profile=chaos_profile)
            for sc in scenarios:
                scenario_counter += 1
                progress.scenario(scenario_counter - 1, total_scenarios, sc.perturbation_id)
                t0_sc = _time.monotonic()
                mutated = apply_perturbation(baseline, sc)
                destructive = analyze_destructive_change(
                    baseline,
                    mutated,
                    perturbation_id=sc.perturbation_id,
                    scenario=sc,
                )
                dt_sc = _time.monotonic() - t0_sc
                perturbation_findings.extend([_destructive_to_finding(d) for d in destructive])
                perturbation_trace.append(
                    {
                        "baseline": baseline.case_id,
                        "mutated": mutated.case_id,
                        "perturbation_id": sc.perturbation_id,
                        "kind": sc.kind,
                        "params": sc.params,
                        "finding_count": len(destructive),
                        "duration_s": round(dt_sc, 4),
                    }
                )

        t_perturb = _time.monotonic() - t0_perturb
        progress.done(
            f"Perturbation: {total_scenarios} scenarios, {len(perturbation_findings)} findings"
        )
        perturbation_stats["duration_s"] = round(t_perturb, 2)

    findings.extend(perturbation_findings)
    t_logic_total = _time.monotonic() - t0_logic

    sections: dict[str, Any] = {
        "logic": {
            "coverage": asdict(coverage_summary),
            "coverage_records": [asdict(r) for r in coverage_records],
            "nearby_pairs": len(pairs),
            "logic_finding_count": len(findings) - len(perturbation_findings),
            "duration_s": round(t_logic_total, 2),
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
            "profile": chaos_profile if auto_perturb else "disabled",
            "scenario_count": len(perturbation_trace),
            "finding_count": len(perturbation_findings),
            "dedup_skipped": perturbation_stats.get("dedup_skipped", 0),
            "unique_baselines": perturbation_stats.get("unique_baselines", 0),
            "duration_s": perturbation_stats.get("duration_s", 0),
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


def _convert_claim_to_xr_file(
    claim_path: str,
    xrd_path: str,
    composition_path: str,
) -> str | None:
    """Read a Claim YAML, convert to XR, write to a temp file.

    Returns the temp file path on success, or ``None`` on error.
    """
    from xptest.render import claim_to_xr

    try:
        with open(claim_path) as fh:
            claim_doc = yaml.safe_load(fh)
        with open(xrd_path) as fh:
            xrd_doc = yaml.safe_load(fh)
        with open(composition_path) as fh:
            comp_doc = yaml.safe_load(fh)
    except Exception as exc:
        sys.stderr.write(f"xptest: failed to read claim/xrd/composition — {exc}\n")
        return None

    xr_doc = claim_to_xr(claim_doc, xrd_doc, comp_doc)

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix="-xr.yaml", prefix="xptest-claim-", delete=False
    )
    yaml.safe_dump(xr_doc, tmp, sort_keys=False)
    tmp.close()

    claim_name = claim_doc.get("metadata", {}).get("name", "?")
    claim_ns = claim_doc.get("metadata", {}).get("namespace", "default")
    sys.stderr.write(
        f"xptest: converted claim {claim_ns}/{claim_name} → XR ({xr_doc['kind']}) at {tmp.name}\n"
    )
    return tmp.name


def _match_claims_to_entries(
    claims_dir: str,
    entries: list,
) -> dict[str, str]:
    """Match Claim YAMLs in a directory to scan entries via XRD claimNames.

    Returns a dict mapping ``xrd_path → temp_xr_path`` for each matched claim.
    """
    from xptest.render import claim_to_xr

    claims_path = Path(claims_dir)
    if not claims_path.is_dir():
        sys.stderr.write(f"xptest: --claims-dir '{claims_dir}' is not a directory\n")
        return {}

    # Load all claim YAMLs
    claim_docs: list[tuple[str, dict]] = []
    for p in sorted(claims_path.glob("**/*.yaml")):
        try:
            with open(p) as fh:
                for doc in yaml.safe_load_all(fh):
                    if doc and isinstance(doc, dict):
                        claim_docs.append((str(p), doc))
        except Exception:
            continue
    for p in sorted(claims_path.glob("**/*.yml")):
        try:
            with open(p) as fh:
                for doc in yaml.safe_load_all(fh):
                    if doc and isinstance(doc, dict):
                        claim_docs.append((str(p), doc))
        except Exception:
            continue

    # Build index: claim_kind → [(path, doc)]
    claim_by_kind: dict[str, list[tuple[str, dict]]] = {}
    for path, doc in claim_docs:
        kind = doc.get("kind", "")
        claim_by_kind.setdefault(kind, []).append((path, doc))

    # Match entries to claims via XRD claimNames.kind
    result: dict[str, str] = {}
    for entry in entries:
        try:
            with open(entry.xrd_path) as fh:
                xrd_doc = yaml.safe_load(fh)
            with open(entry.composition_path) as fh:
                comp_doc = yaml.safe_load(fh)
        except Exception:
            continue

        claim_kind = xrd_doc.get("spec", {}).get("claimNames", {}).get("kind", "")
        if not claim_kind or claim_kind not in claim_by_kind:
            continue

        # Use the first matching claim for this composition
        claim_path, claim_doc = claim_by_kind[claim_kind][0]
        xr_doc = claim_to_xr(claim_doc, xrd_doc, comp_doc)

        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix="-xr.yaml", prefix="xptest-claim-", delete=False
        )
        yaml.safe_dump(xr_doc, tmp, sort_keys=False)
        tmp.close()

        claim_name = claim_doc.get("metadata", {}).get("name", "?")
        sys.stderr.write(
            f"xptest: matched claim '{claim_name}' ({claim_kind}) → {entry.composition_name}\n"
        )
        result[entry.xrd_path] = tmp.name

    return result


def _resolve_input_path(path: str) -> str:
    """Resolve a CLI file path from common repository layouts.

    Supports direct paths, and package-root-prefixed paths used in this workspace,
    such as ``pkg/...`` resolving to ``xplane-pkg/pkg/...``.
    """
    p = Path(path)
    if p.exists():
        return str(p)

    if p.is_absolute():
        raise FileNotFoundError(path)

    candidates: list[Path] = []

    # Common roots in this thesis workspace.
    for root in ("xplane-pkg", "crossplane-composition-tester"):
        cand = Path(root) / p
        if cand.exists() and cand.is_file():
            candidates.append(cand)

    # Fallback: find exact suffix match anywhere in the workspace.
    search_suffix = str(p).lstrip("./")
    if search_suffix:
        for match in Path.cwd().glob(f"**/{search_suffix}"):
            if match.is_file():
                candidates.append(match)

    unique = sorted({c.resolve() for c in candidates})
    if len(unique) == 1:
        return str(unique[0])
    if len(unique) > 1:
        options = ", ".join(str(c) for c in unique[:3])
        raise ValueError(f"ambiguous path '{path}' matched multiple files: {options}")

    raise FileNotFoundError(path)


def _destructive_to_finding(destructive) -> Finding:
    message = _format_destructive_message(destructive)

    return Finding(
        layer=6,
        rule=destructive.finding_id,
        resource=destructive.resource_id,
        path="",
        severity=destructive.severity,
        message=message,
        remediation=destructive.remediation,
        finding_id=destructive.finding_id,
        category=destructive.category,
        case_id=destructive.case_id,
        baseline_case_id=destructive.baseline_case_id,
        perturbation_id=destructive.perturbation_id,
        evidence=destructive.evidence,
    )


def _format_destructive_message(destructive) -> str:
    evidence = destructive.evidence or {}

    if destructive.finding_id == "C1-disappearance-risk":
        removed = evidence.get("removed") or destructive.resource_id or "unknown resource"
        return (
            "A rendered resource disappeared after a small perturbation. "
            f"Removed resource: {removed}."
        )

    if destructive.finding_id == "C2-replacement-risk":
        removed = evidence.get("removed") or []
        added = evidence.get("added") or []
        removed_text = ", ".join(str(v) for v in removed[:3]) or "none"
        added_text = ", ".join(str(v) for v in added[:3]) or "none"
        return (
            "Resource replacement pattern detected under perturbation. "
            f"Removed ({len(removed)}): {removed_text}. "
            f"Added ({len(added)}): {added_text}."
        )

    if destructive.finding_id == "C3-cascade-risk":
        removed = evidence.get("removed") or []
        return (
            "One perturbation caused multiple resources to disappear, which suggests "
            "a cascade dependency. "
            f"Removed resources: {len(removed)}."
        )

    if destructive.finding_id == "C4-unsafe-dependency-drift":
        baseline_edges = evidence.get("baseline_edges") or []
        mutated_edges = evidence.get("mutated_edges") or []
        return (
            "Dependency graph changed after perturbation. "
            f"Edges before: {len(baseline_edges)}, after: {len(mutated_edges)}."
        )

    if destructive.finding_id == "C5-partial-output-risk":
        baseline = evidence.get("baseline_count")
        mutated = evidence.get("mutated_count")
        if baseline is not None and mutated is not None:
            return (
                "Render output collapsed to a partial set after perturbation. "
                f"Resources before: {baseline}, after: {mutated}."
            )
        return "Render output collapsed to a partial set after perturbation."

    return f"{destructive.finding_id}: offline perturbation risk detected"


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


def _chaos_structure_key(snapshot) -> str:
    payload = {
        "resource_ids": sorted([n.resource_id for n in snapshot.resources]),
        "edges": sorted([list(e) for e in snapshot.edges]),
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# scan subcommand — package-level validation
# ---------------------------------------------------------------------------


def _cmd_scan(args: argparse.Namespace) -> int:
    import time

    from xptest import progress
    from xptest.cache import load_crd_bundle
    from xptest.package import discover_package

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        sys.stderr.write(f"xptest: config error — {exc}\n")
        return 1

    progress.init()

    # Early availability check for auto render mode.
    if args.render_mode == "auto":
        from xptest.render import crossplane_cli_available

        if not crossplane_cli_available():
            progress.step("crossplane CLI not found — falling back to offline mode")
            args.render_mode = "offline"

    # Discover compositions and XRDs
    progress.phase("Discovering compositions")
    result = discover_package(
        root=args.root,
        functions_path=args.functions,
        environment_config_paths=cfg.environment_config_paths,
    )

    if not result.entries:
        progress.warn(f"no Composition+XRD pairs found under '{args.root}'")
        if result.unmatched_compositions:
            progress.step(f"Unmatched compositions: {len(result.unmatched_compositions)}")
        if result.unmatched_xrds:
            progress.step(f"Unmatched XRDs: {len(result.unmatched_xrds)}")
        return 1

    progress.step(f"{len(result.entries)} composition(s) found in {result.scan_duration_s:.2f}s")
    if result.unmatched_compositions:
        progress.step(f"{len(result.unmatched_compositions)} unmatched composition(s) skipped")

    # Load CRD bundle once for all compositions
    crd_cache = load_crd_bundle(cfg.crd_bundle_path)

    # Validate each composition
    progress.phase(f"Validating {len(result.entries)} composition(s)")
    composition_reports: list[dict[str, Any]] = []
    total_findings = 0
    has_critical = False
    pass_count = 0
    fail_count = 0
    error_count = 0

    # Build claim → XR mapping if --claims-dir was provided
    claim_xr_map: dict[str, str] = {}  # xrd_path → temp XR path
    if getattr(args, "claims_dir", None):
        claim_xr_map = _match_claims_to_entries(args.claims_dir, result.entries)
        if claim_xr_map:
            progress.step(f"{len(claim_xr_map)} claim(s) matched to compositions")

    for idx, entry in enumerate(result.entries):
        comp_start = time.monotonic()
        progress.combo(idx, len(result.entries), entry.composition_name)

        xr_path = claim_xr_map.get(entry.xrd_path)

        try:
            obj = load(
                composition_path=entry.composition_path,
                xrd_path=entry.xrd_path,
                crd_bundle_path=cfg.crd_bundle_path,
                xr_path=xr_path,
                functions_path=entry.functions_path,
                observed_resources_path=None,
                environment_config_paths=entry.environment_config_paths,
                render_mode=args.render_mode,
            )
        except LoadError as exc:
            comp_report = {
                "composition": entry.composition_name,
                "composition_path": entry.composition_path,
                "xrd_path": entry.xrd_path,
                "error": str(exc),
                "findings": [],
                "duration_s": time.monotonic() - comp_start,
            }
            composition_reports.append(comp_report)
            error_count += 1
            progress.warn(f"load error: {exc}")
            continue

        vr = run_validations(
            obj,
            cfg,
            halt_on_critical=args.halt_on_critical,
            crd_cache=crd_cache,
        )

        finding_dicts = [
            {
                "layer": f.layer,
                "rule": f.rule,
                "resource": f.resource,
                "path": f.path,
                "severity": f.severity.value,
                "message": f.message,
                "remediation": f.remediation,
            }
            for f in vr.findings
        ]

        comp_duration = time.monotonic() - comp_start
        comp_report = {
            "composition": entry.composition_name,
            "composition_path": entry.composition_path,
            "xrd_path": entry.xrd_path,
            "findings": finding_dicts,
            "finding_count": len(finding_dicts),
            "halted_layer": vr.halted_layer,
            "duration_s": round(comp_duration, 3),
        }
        composition_reports.append(comp_report)
        total_findings += len(finding_dicts)

        critical_count = sum(1 for f in vr.findings if f.severity == Severity.CRITICAL)
        warning_count = sum(1 for f in vr.findings if f.severity == Severity.WARNING)
        if critical_count:
            has_critical = True
            fail_count += 1
        else:
            pass_count += 1

        status = "PASS" if not critical_count else "FAIL"
        progress.step(
            f"  [{status}] {len(finding_dicts)} findings "
            f"(C={critical_count} W={warning_count}) "
            f"{comp_duration:.2f}s"
        )

    total_duration = progress.elapsed()

    # Write report
    report = {
        "scan_root": args.root,
        "compositions_found": len(result.entries),
        "unmatched_compositions": result.unmatched_compositions,
        "unmatched_xrds": result.unmatched_xrds,
        "total_findings": total_findings,
        "total_duration_s": round(total_duration, 3),
        "compositions": composition_reports,
    }

    Path(args.output).write_text(json.dumps(report, indent=2) + "\n")

    progress.phase("Scan complete")
    progress.step(f"Compositions: {len(result.entries)}")
    progress.step(f"Pass: {pass_count}  Fail: {fail_count}  Error: {error_count}")
    progress.step(f"Total findings: {total_findings}")
    progress.step(f"Duration: {total_duration:.2f}s")
    progress.step(f"Report: {args.output}")

    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
