"""Project a single assessment's graph from Postgres into Neo4j.

Postgres is the source of truth; Neo4j is a derived, rebuildable read-model.
Projection is delete-then-load scoped by assessment_id, so it is idempotent.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.config import settings
from adbygod_api.core.graph import neo4j_client
from adbygod_api.models import Entity, GraphEdge

log = logging.getLogger(__name__)

# Entity columns carried onto the node (primitives only; nested JSON stays in PG).
_ENTITY_PROPS = (
    "object_sid", "sam_account_name", "distinguished_name", "dns_hostname",
    "domain", "display_name", "is_enabled", "is_admin_count", "is_sensitive",
    "is_protected_user", "is_crown_jewel", "tier",
)


def _entity_row(ent: Entity) -> dict[str, Any]:
    etype = ent.entity_type.value if ent.entity_type else "UNKNOWN"
    row: dict[str, Any] = {
        "id": str(ent.id),
        "assessment_id": str(ent.assessment_id),
        "entity_type": etype,
    }
    for prop in _ENTITY_PROPS:
        row[prop] = getattr(ent, prop, None)
    return row


def _edge_row(edge: GraphEdge) -> dict[str, Any]:
    etype = edge.edge_type.value if edge.edge_type else "UNKNOWN"
    return {
        "id": str(edge.id),
        "assessment_id": str(edge.assessment_id),
        "source_id": str(edge.source_id),
        "target_id": str(edge.target_id),
        "edge_type": etype,
        "risk_weight": float(edge.risk_weight) if edge.risk_weight is not None else 0.5,
        "provenance": edge.provenance or "",
        "edge_confidence": float(getattr(edge, "edge_confidence", 1.0) or 1.0),
        "edge_provenance_type": getattr(edge, "edge_provenance_type", "collected") or "collected",
    }


def _batched(seq: list[Any], size: int) -> Iterable[list[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


_DELETE_CYPHER = "MATCH (n:Entity {assessment_id: $aid}) DETACH DELETE n"

_LOAD_NODES_CYPHER = """
UNWIND $rows AS row
MERGE (n:Entity {id: row.id})
SET n += row
WITH n, row
CALL apoc.create.addLabels(n, [row.entity_type]) YIELD node
RETURN count(node)
"""

_LOAD_EDGES_CYPHER = """
UNWIND $rows AS row
MATCH (s:Entity {id: row.source_id})
MATCH (t:Entity {id: row.target_id})
CALL apoc.merge.relationship(
    s, row.edge_type,
    {id: row.id},
    {assessment_id: row.assessment_id, risk_weight: row.risk_weight,
     provenance: row.provenance, edge_confidence: row.edge_confidence,
     edge_provenance_type: row.edge_provenance_type},
    t,
    {}
) YIELD rel
RETURN count(rel)
"""


async def reproject_assessment(db: AsyncSession, assessment_id: str) -> dict[str, int]:
    """Rebuild one assessment's Neo4j subgraph from Postgres. Idempotent.

    The delete + batched loads run as separate auto-commit statements rather
    than one transaction, so a mid-projection failure can leave a partial
    subgraph. That is acceptable because Neo4j is a derived read-model: the
    same call re-run from Postgres (the source of truth) restores it.

    Returns the number of rows submitted (the Postgres counts), not the rows
    Neo4j actually created.
    """
    ents = (await db.execute(
        select(Entity).where(Entity.assessment_id == assessment_id)
    )).scalars().all()
    edges = (await db.execute(
        select(GraphEdge).where(GraphEdge.assessment_id == assessment_id)
    )).scalars().all()

    node_rows = [_entity_row(e) for e in ents]
    edge_rows = [_edge_row(e) for e in edges]
    batch = settings.GRAPH_PROJECT_BATCH_SIZE

    driver = neo4j_client.get_driver()
    async with driver.session(database=settings.NEO4J_DATABASE) as session:
        await session.run(_DELETE_CYPHER, aid=str(assessment_id))
        for chunk in _batched(node_rows, batch):
            await session.run(_LOAD_NODES_CYPHER, rows=chunk)
        for chunk in _batched(edge_rows, batch):
            await session.run(_LOAD_EDGES_CYPHER, rows=chunk)

    log.info("Projected assessment %s: %d nodes, %d edges",
             assessment_id, len(node_rows), len(edge_rows))
    return {"nodes": len(node_rows), "edges": len(edge_rows)}
