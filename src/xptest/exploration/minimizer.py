"""Failing input minimizer (§3.3.2).

When an invariant violation is found, the failing input is minimized
and stored as a regression artifact. This keeps the suite compact
while preserving fault reproducibility.

Uses a binary-search reduction strategy: iteratively remove parameters
from the failing input and re-check whether the violation reproduces.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable


def minimize_input(
    failing_spec: dict[str, Any],
    check_fn: Callable[[dict[str, Any]], bool],
    max_iterations: int = 50,
) -> dict[str, Any]:
    """Minimize a failing input spec to its essential parameters.

    Args:
        failing_spec: The full spec dict that triggers the violation.
        check_fn: A function that takes a spec dict and returns True
                  if the violation still reproduces, False otherwise.
        max_iterations: Safety limit on reduction iterations.

    Returns:
        A minimal spec dict that still triggers the violation.
    """
    if not failing_spec:
        return failing_spec

    # Start with all keys
    current = dict(failing_spec)
    keys = list(current.keys())

    iteration = 0
    for key in keys:
        if iteration >= max_iterations:
            break
        iteration += 1

        # Try removing this key
        candidate = {k: v for k, v in current.items() if k != key}
        if not candidate:
            # Don't reduce to empty
            continue

        if check_fn(candidate):
            # Violation still reproduces without this key — remove it
            current = candidate

    return current


def save_regression_artifact(
    minimized_spec: dict[str, Any],
    violation_rule: str,
    case_id: str,
    output_dir: str = "regressions",
) -> str:
    """Save a minimized failing input as a regression artifact.

    Returns the path to the saved artifact.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    safe_rule = violation_rule.replace("/", "_")
    safe_case = case_id.replace("|", "_").replace(":", "_")
    filename = f"{safe_rule}_{safe_case}.json"
    path = out / filename

    artifact = {
        "rule": violation_rule,
        "case_id": case_id,
        "minimized_spec": minimized_spec,
    }
    path.write_text(
        json.dumps(artifact, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )
    return str(path)
