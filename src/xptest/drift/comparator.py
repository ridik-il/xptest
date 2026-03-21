"""Generic field-level comparison between desired and observed resource state.

Compares a desired spec (from composition YAML) to an observed state (from AWS API).
Produces a list of field mismatches with JSON paths.

Handles:
- Type normalization (boolean True/False vs strings "true"/"false")
- Ignores AWS-managed fields not present in the desired spec
- Recursive nested dict/list comparison
"""

from __future__ import annotations

from typing import Any

# AWS-managed fields that should never be flagged as drift.
# These are set by AWS and not declared in compositions.
_AWS_MANAGED_FIELDS = frozenset({
    "arn",
    "createDate",
    "creationDate",
    "lastModifiedDate",
    "ownerId",
    "accountId",
    "requesterId",
    "vpcId",
    "subnetId",
    "securityGroupId",
    "routeTableId",
    "dbInstanceIdentifier",
    "dbInstanceArn",
    "endpoint",
    "instanceCreateTime",
    "latestRestorableTime",
    "roleId",
    "roleLastUsed",
    "uniqueId",
})


def compare_fields(
    desired: dict[str, Any],
    observed: dict[str, Any],
    prefix: str = "",
) -> list[dict[str, str]]:
    """Compare desired fields against observed state.

    Only fields present in *desired* are checked. Extra fields in *observed*
    that are not in *desired* are silently ignored (they are AWS-managed).

    Returns a list of mismatch dicts: {"path": ..., "desired": ..., "observed": ...}
    """
    mismatches: list[dict[str, str]] = []
    _compare_recursive(desired, observed, prefix, mismatches)
    return mismatches


def _compare_recursive(
    desired: Any,
    observed: Any,
    path: str,
    mismatches: list[dict[str, str]],
) -> None:
    if desired is None:
        return

    if isinstance(desired, dict):
        if not isinstance(observed, dict):
            mismatches.append({
                "path": path or "/",
                "desired": str(desired),
                "observed": str(observed),
            })
            return
        for key in desired:
            if key in _AWS_MANAGED_FIELDS:
                continue
            child_path = f"{path}/{key}" if path else key
            if key not in observed:
                mismatches.append({
                    "path": child_path,
                    "desired": str(desired[key]),
                    "observed": "<missing>",
                })
            else:
                _compare_recursive(desired[key], observed[key], child_path, mismatches)

    elif isinstance(desired, list):
        if not isinstance(observed, list):
            mismatches.append({
                "path": path,
                "desired": str(desired),
                "observed": str(observed),
            })
            return
        for i, item in enumerate(desired):
            child_path = f"{path}/{i}"
            if i >= len(observed):
                mismatches.append({
                    "path": child_path,
                    "desired": str(item),
                    "observed": "<missing>",
                })
            else:
                _compare_recursive(item, observed[i], child_path, mismatches)

    else:
        if not _values_equal(desired, observed):
            mismatches.append({
                "path": path,
                "desired": str(desired),
                "observed": str(observed),
            })


def _values_equal(desired: Any, observed: Any) -> bool:
    """Compare two scalar values with type normalization."""
    if desired == observed:
        return True

    # Normalize booleans vs strings
    if isinstance(desired, bool) and isinstance(observed, str):
        return str(desired).lower() == observed.lower()
    if isinstance(desired, str) and isinstance(observed, bool):
        return desired.lower() == str(observed).lower()

    # Normalize int/float comparisons
    if isinstance(desired, (int, float)) and isinstance(observed, (int, float)):
        return desired == observed

    # Normalize string vs number
    try:
        return str(desired) == str(observed)
    except (ValueError, TypeError):
        return False
