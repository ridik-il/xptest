"""Tests for the metrics module."""

from __future__ import annotations

from xptest.metrics import LayerMetrics, compare


class TestCompare:
    def test_perfect_match(self):
        expected = [
            {"layer": 2, "rule": "L2-02/dependency-cycle", "severity": "CRITICAL"},
        ]
        actual = [
            {"layer": 2, "rule": "L2-02/dependency-cycle", "severity": "CRITICAL"},
        ]
        tp, fp, fn, sev_mm = compare(actual, expected)
        assert (tp, fp, fn, sev_mm) == (1, 0, 0, 0)

    def test_false_negative(self):
        expected = [
            {"layer": 2, "rule": "L2-02/dependency-cycle", "severity": "CRITICAL"},
            {"layer": 2, "rule": "L2-03/dangling-reference", "severity": "CRITICAL"},
        ]
        actual = [
            {"layer": 2, "rule": "L2-02/dependency-cycle", "severity": "CRITICAL"},
        ]
        tp, fp, fn, sev_mm = compare(actual, expected)
        assert tp == 1
        assert fn == 1
        assert fp == 0

    def test_false_positive(self):
        expected = [
            {"layer": 2, "rule": "L2-02/dependency-cycle", "severity": "CRITICAL"},
        ]
        actual = [
            {"layer": 2, "rule": "L2-02/dependency-cycle", "severity": "CRITICAL"},
            {"layer": 1, "rule": "L1-03/duplicate-name", "severity": "WARNING"},
        ]
        tp, fp, fn, sev_mm = compare(actual, expected)
        assert tp == 1
        assert fp == 1
        assert fn == 0

    def test_severity_mismatch(self):
        expected = [
            {"layer": 3, "rule": "tag/mandatory-keys", "severity": "WARNING"},
        ]
        actual = [
            {"layer": 3, "rule": "tag/mandatory-keys", "severity": "CRITICAL"},
        ]
        tp, fp, fn, sev_mm = compare(actual, expected)
        assert tp == 1
        assert sev_mm == 1
        assert fp == 0
        assert fn == 0

    def test_empty(self):
        tp, fp, fn, sev_mm = compare([], [])
        assert (tp, fp, fn, sev_mm) == (0, 0, 0, 0)

    def test_all_false_negatives(self):
        expected = [
            {"layer": 2, "rule": "L2-02/dependency-cycle", "severity": "CRITICAL"},
        ]
        tp, fp, fn, sev_mm = compare([], expected)
        assert tp == 0
        assert fn == 1

    def test_all_false_positives(self):
        actual = [
            {"layer": 1, "rule": "L1-01/schema-error", "severity": "CRITICAL"},
        ]
        tp, fp, fn, sev_mm = compare(actual, [])
        assert tp == 0
        assert fp == 1


class TestLayerMetrics:
    def test_perfect_recall(self):
        lm = LayerMetrics(layer=2, tp=5, fp=0, fn=0)
        assert lm.recall == 1.0
        assert lm.precision == 1.0
        assert lm.fpr == 0.0

    def test_zero_recall(self):
        lm = LayerMetrics(layer=2, tp=0, fp=0, fn=3)
        assert lm.recall == 0.0

    def test_mixed(self):
        lm = LayerMetrics(layer=2, tp=3, fp=1, fn=1)
        assert lm.recall == 3 / 4
        assert lm.precision == 3 / 4
        assert lm.fpr == 1 / 4

    def test_empty_defaults_to_perfect(self):
        lm = LayerMetrics(layer=1)
        assert lm.recall == 1.0
        assert lm.precision == 1.0
        assert lm.fpr == 0.0
