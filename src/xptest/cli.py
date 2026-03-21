"""xptest CLI entry point.

Usage:
    xptest validate --composition <path> --xrd <path> [--config <path>] [--output <path>]

Subcommands planned:
    validate   Run Layers 1–4 against a Composition + XRD pair.
    explore    Run the Behavioral Exploration Module (Phase 5).
    drift      Run Stage 3 drift detection (Phase 4).
"""

from __future__ import annotations

import argparse
import sys

from xptest.config import load_config
from xptest.layer1 import static as layer1
from xptest.layer2 import dependency as layer2
from xptest.layer4 import reporting as layer4
from xptest.loader import LoadError, load
from xptest.models import Severity


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

    return parser


def _cmd_validate(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)

    try:
        obj = load(
            composition_path=args.composition,
            xrd_path=args.xrd,
            crd_bundle_path=cfg.crd_bundle_path,
        )
    except LoadError as exc:
        sys.stderr.write(f"xptest: load error — {exc}\n")
        return 1

    all_findings = []

    # Layer 1
    l1_findings = layer1.run(obj)
    all_findings.extend(l1_findings)

    has_critical = any(f.severity == Severity.CRITICAL for f in l1_findings)
    if has_critical and args.halt_on_critical:
        sys.stderr.write("xptest: CRITICAL finding(s) in Layer 1 — halting pipeline.\n")
        return layer4.write(all_findings, output_path=args.output)

    # Layer 2
    l2_findings = layer2.run(obj)
    all_findings.extend(l2_findings)

    return layer4.write(all_findings, output_path=args.output)


if __name__ == "__main__":
    sys.exit(main())
