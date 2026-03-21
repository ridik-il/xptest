"""Coverage approximation and nearby input utilities."""

from __future__ import annotations

import hashlib
import json
from itertools import combinations
from typing import Any

from xptest.logic.models import (
    CoverageRecord,
    LogicCoverageSummary,
    NearbyPair,
    RenderedGraphSnapshot,
)


def compute_coverage(
    snapshots: list[RenderedGraphSnapshot],
) -> tuple[list[CoverageRecord], LogicCoverageSummary]:
    records: list[CoverageRecord] = []
    for s in snapshots:
        presence = sorted([n.resource_id for n in s.resources])
        field_pairs = sorted(_collect_field_pairs(s))
        records.append(
            CoverageRecord(
                case_id=s.case_id,
                resource_presence_signature=_hash(presence),
                field_signature=_hash(field_pairs),
            )
        )

    summary = LogicCoverageSummary(
        total_cases=len(snapshots),
        unique_graphs=len({s.graph_hash for s in snapshots}),
        unique_presence_signatures=len({r.resource_presence_signature for r in records}),
        unique_field_signatures=len({r.field_signature for r in records}),
    )
    return records, summary


def nearby_pairs(
    snapshots: list[RenderedGraphSnapshot],
    max_distance: int = 1,
) -> list[NearbyPair]:
    pairs: list[NearbyPair] = []
    for a, b in combinations(snapshots, 2):
        d = _input_distance(a.input_flat, b.input_flat)
        if d <= max_distance:
            pairs.append(NearbyPair(case_a=a.case_id, case_b=b.case_id, distance=d))
    return sorted(pairs, key=lambda p: (p.distance, p.case_a, p.case_b))


def flatten_input_spec(spec: dict[str, Any], prefix: str = "spec") -> dict[str, Any]:
    result: dict[str, Any] = {}
    for k, v in sorted(spec.items()):
        key = f"{prefix}.{k}"
        if isinstance(v, dict):
            result.update(flatten_input_spec(v, key))
        else:
            result[key] = v
    return result


def _collect_field_pairs(snapshot: RenderedGraphSnapshot) -> list[str]:
    pairs: list[str] = []
    for n in snapshot.resources:
        flat = flatten_input_spec(n.spec, "spec")
        for k, v in sorted(flat.items()):
            pairs.append(f"{n.resource_id}:{k}={v}")
    return pairs


def _input_distance(a: dict[str, Any], b: dict[str, Any]) -> int:
    keys = sorted(set(a.keys()) | set(b.keys()))
    dist = 0
    for k in keys:
        if a.get(k) != b.get(k):
            dist += 1
    return dist


def _hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
