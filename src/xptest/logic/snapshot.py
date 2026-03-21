"""Snapshot and identity helpers for rendered composition graphs."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from xptest.logic.models import RenderedGraphSnapshot, RenderedResourceNode
from xptest.models import CompositionObject


def build_snapshot(
    obj: CompositionObject,
    case_id: str,
    input_flat: dict[str, Any],
) -> RenderedGraphSnapshot:
    nodes = [
        RenderedResourceNode(
            resource_id=resolve_resource_id(r, idx),
            role=resolve_semantic_role(r, idx),
            api_version=r.api_version,
            kind=r.kind,
            name=r.name,
            spec=r.spec,
            identity_source=_identity_source(r),
        )
        for idx, r in enumerate(obj.resources)
    ]
    nodes = sorted(nodes, key=lambda n: n.resource_id)

    edges = infer_dependency_edges(nodes)
    graph_hash = _stable_hash(
        {
            "nodes": [
                {
                    "resource_id": n.resource_id,
                    "api_version": n.api_version,
                    "kind": n.kind,
                    "name": n.name,
                    "spec": n.spec,
                }
                for n in nodes
            ],
            "edges": sorted(edges),
        }
    )
    return RenderedGraphSnapshot(
        case_id=case_id,
        input_flat=input_flat,
        resources=nodes,
        edges=edges,
        graph_hash=graph_hash,
    )


def resolve_resource_id(resource, idx: int) -> str:
    if resource.name:
        return f"{resource.api_version}|{resource.kind}|{resource.name}"
    return f"{resource.api_version}|{resource.kind}|idx-{idx}"


def resolve_semantic_role(resource, idx: int) -> str:
    if resource.name:
        return resource.name
    return f"{resource.kind.lower()}-{idx}"


def infer_dependency_edges(nodes: list[RenderedResourceNode]) -> list[tuple[str, str]]:
    """Infer lightweight dependency edges from rendered specs.

    Deterministic heuristic: if node A's role or name appears in string fields of node B,
    infer A -> B.
    """
    edges: set[tuple[str, str]] = set()
    lookup = [(n.resource_id, n.role, n.name) for n in nodes]
    for consumer in nodes:
        blob = _as_text(consumer.spec)
        for producer_id, producer_role, producer_name in lookup:
            if producer_id == consumer.resource_id:
                continue
            if producer_role and producer_role in blob:
                edges.add((producer_id, consumer.resource_id))
                continue
            if producer_name and producer_name in blob:
                edges.add((producer_id, consumer.resource_id))
    return sorted(edges)


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _stable_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _identity_source(resource) -> str:
    return "composition-resource-name" if resource.name else "index-fallback"
