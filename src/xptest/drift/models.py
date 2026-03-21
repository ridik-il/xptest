"""Drift detection data models.

Extends the base Finding dataclass with drift-specific fields as defined
in framework-design.md §3.4: desired, observed, resource_arn.
"""

from __future__ import annotations

from dataclasses import dataclass

from xptest.models import Finding


@dataclass
class DriftFinding(Finding):
    """A finding produced by comparing desired (composition) state to observed (AWS) state."""

    desired: str = ""
    observed: str = ""
    resource_arn: str = ""


class DriftError(RuntimeError):
    """Raised when drift detection encounters an unrecoverable error."""

    pass
