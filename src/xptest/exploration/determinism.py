"""Determinism score — run same inputs twice, compare outputs (§3.3.4).

Determinism score = identical_outputs / total_inputs.
A score of 1.0 means the framework is fully deterministic.
"""

from __future__ import annotations

from typing import Any

from xptest.logic.models import RenderedGraphSnapshot


def compute_determinism_score(
    run_a: list[RenderedGraphSnapshot],
    run_b: list[RenderedGraphSnapshot],
) -> dict[str, Any]:
    """Compare two runs of the same inputs and return determinism metrics.

    Both runs must have the same length and correspond to the same inputs
    in order.  Comparison uses the stable graph_hash from each snapshot.

    Returns:
        {
            "total_inputs": N,
            "identical_outputs": M,
            "determinism_score": M/N,
        }
    """
    total = len(run_a)
    if total == 0:
        return {
            "total_inputs": 0,
            "identical_outputs": 0,
            "determinism_score": 1.0,
        }

    identical = 0
    for sa, sb in zip(run_a, run_b):
        if sa.graph_hash == sb.graph_hash:
            identical += 1

    score = identical / total
    return {
        "total_inputs": total,
        "identical_outputs": identical,
        "determinism_score": round(score, 4),
    }
