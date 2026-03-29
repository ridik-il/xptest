"""Metric collection for thesis evaluation (Chapter 5).

Compares actual findings (findings.json) against ground-truth labels
(expected.json) and computes per-layer metrics:
  - True Positives (TP), False Positives (FP), False Negatives (FN)
  - Recall = TP / (TP + FN)
  - Precision = TP / (TP + FP)
  - False Positive Rate (FPR) approximation = FP / (FP + TP)

Matching is rule-based: a finding matches an expected entry if
(layer, rule) are equal. Severity is checked but a mismatch counts
as a TP with a severity-mismatch annotation (not a FP).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class LayerMetrics:
    layer: int
    tp: int = 0
    fp: int = 0
    fn: int = 0
    severity_mismatches: int = 0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 1.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 1.0

    @property
    def fpr(self) -> float:
        denom = self.fp + self.tp
        return self.fp / denom if denom > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "severity_mismatches": self.severity_mismatches,
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "fpr": round(self.fpr, 4),
        }


@dataclass
class FixtureResult:
    fixture: str
    expected_count: int = 0
    actual_count: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    details: list[str] = field(default_factory=list)


def compare(
    actual: list[dict[str, Any]],
    expected: list[dict[str, Any]],
) -> tuple[int, int, int, int]:
    """Compare actual findings against expected labels.

    Returns (tp, fp, fn, severity_mismatches).
    """
    matched_expected = [False] * len(expected)

    tp = 0
    severity_mismatches = 0

    for a in actual:
        a_key = (a["layer"], a["rule"])
        for i, e in enumerate(expected):
            if matched_expected[i]:
                continue
            if (e["layer"], e["rule"]) == a_key:
                matched_expected[i] = True
                tp += 1
                if a.get("severity") != e.get("severity"):
                    severity_mismatches += 1
                break

    fn = sum(1 for m in matched_expected if not m)
    fp = len(actual) - tp

    return tp, fp, fn, severity_mismatches


def compute_fixture_metrics(
    fixtures_dir: Path,
    findings_by_fixture: dict[str, list[dict[str, Any]]],
) -> list[FixtureResult]:
    """Compute per-fixture metrics.

    Args:
        fixtures_dir: Root fixtures directory.
        findings_by_fixture: Map of fixture stem name to actual findings list.
    """
    results = []
    for stem, actual in sorted(findings_by_fixture.items()):
        # Find expected.json
        expected_path = None
        for subdir in ("valid", "dep-errors", "policy-violations"):
            candidate = fixtures_dir / subdir / f"{stem}-expected.json"
            if candidate.exists():
                expected_path = candidate
                break

        if expected_path is None:
            results.append(FixtureResult(
                fixture=stem,
                actual_count=len(actual),
                details=["No expected.json found"],
            ))
            continue

        expected = json.loads(expected_path.read_text())
        tp, fp, fn, sev_mm = compare(actual, expected)

        fr = FixtureResult(
            fixture=stem,
            expected_count=len(expected),
            actual_count=len(actual),
            tp=tp,
            fp=fp,
            fn=fn,
        )
        if fn > 0:
            fr.details.append(f"{fn} expected finding(s) not detected")
        if fp > 0:
            fr.details.append(f"{fp} unexpected finding(s)")
        if sev_mm > 0:
            fr.details.append(f"{sev_mm} severity mismatch(es)")

        results.append(fr)

    return results


def aggregate_by_layer(
    fixture_results: list[FixtureResult],
    findings_by_fixture: dict[str, list[dict[str, Any]]],
    fixtures_dir: Path,
) -> dict[int, LayerMetrics]:
    """Aggregate metrics per layer across all fixtures."""
    layer_metrics: dict[int, LayerMetrics] = {}

    for stem, actual in findings_by_fixture.items():
        expected_path = None
        for subdir in ("valid", "dep-errors", "policy-violations"):
            candidate = fixtures_dir / subdir / f"{stem}-expected.json"
            if candidate.exists():
                expected_path = candidate
                break

        if expected_path is None:
            continue

        expected = json.loads(expected_path.read_text())

        # Group by layer
        layers = set()
        for e in expected:
            layers.add(e["layer"])
        for a in actual:
            layers.add(a["layer"])

        for layer in layers:
            if layer not in layer_metrics:
                layer_metrics[layer] = LayerMetrics(layer=layer)

            layer_expected = [e for e in expected if e["layer"] == layer]
            layer_actual = [a for a in actual if a["layer"] == layer]
            tp, fp, fn, sev_mm = compare(layer_actual, layer_expected)

            lm = layer_metrics[layer]
            lm.tp += tp
            lm.fp += fp
            lm.fn += fn
            lm.severity_mismatches += sev_mm

    return layer_metrics


def generate_report(
    layer_metrics: dict[int, LayerMetrics],
    fixture_results: list[FixtureResult],
) -> dict[str, Any]:
    """Generate the full evaluation report as a dict."""
    return {
        "summary": {
            layer: lm.to_dict()
            for layer, lm in sorted(layer_metrics.items())
        },
        "fixtures": [
            {
                "fixture": fr.fixture,
                "expected": fr.expected_count,
                "actual": fr.actual_count,
                "tp": fr.tp,
                "fp": fr.fp,
                "fn": fr.fn,
                "details": fr.details,
            }
            for fr in fixture_results
        ],
    }
