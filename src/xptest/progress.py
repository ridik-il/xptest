"""Progress logging for long-running xptest operations.

Provides structured, human-readable progress output so that deep validation
runs appear visibly alive.  All output goes to stderr to keep stdout clean
for machine-readable results.
"""

from __future__ import annotations

import sys
import time
from contextlib import contextmanager
from typing import TextIO

_out: TextIO = sys.stderr
_start: float = 0.0
_phase_start: float = 0.0


def init() -> None:
    """Initialise the global timer."""
    global _start
    _start = time.monotonic()


def elapsed() -> float:
    """Wall-clock seconds since init()."""
    return time.monotonic() - _start


def _ts() -> str:
    """Human timestamp like [  3.2s]."""
    return f"[{elapsed():6.1f}s]"


def phase(name: str) -> None:
    """Log the start of a major phase."""
    global _phase_start
    _phase_start = time.monotonic()
    _out.write(f"{_ts()} ── {name} ──\n")
    _out.flush()


def step(msg: str) -> None:
    """Log a step within the current phase."""
    _out.write(f"{_ts()}   {msg}\n")
    _out.flush()


def combo(index: int, total: int, label: str) -> None:
    """Log progress on a numbered combination."""
    _out.write(f"{_ts()}   [{index + 1}/{total}] {label}\n")
    _out.flush()


def scenario(index: int, total: int, label: str) -> None:
    """Log progress on a numbered perturbation scenario."""
    _out.write(f"{_ts()}     scenario {index + 1}/{total}: {label}\n")
    _out.flush()


def done(msg: str) -> None:
    """Log completion of a phase with wall time."""
    dt = time.monotonic() - _phase_start
    _out.write(f"{_ts()}   {msg} ({dt:.1f}s)\n")
    _out.flush()


def summary_line(msg: str) -> None:
    """Log a summary stat line."""
    _out.write(f"{_ts()}   {msg}\n")
    _out.flush()


def warn(msg: str) -> None:
    """Log a warning."""
    _out.write(f"{_ts()}   WARN: {msg}\n")
    _out.flush()


@contextmanager
def timed(label: str):
    """Context manager that logs start and elapsed time."""
    t0 = time.monotonic()
    step(f"{label} ...")
    yield
    dt = time.monotonic() - t0
    step(f"{label} done ({dt:.1f}s)")
