"""Cypher-backed graph queries, scoped per assessment. Replaces ADGraphAnalyzer."""
from __future__ import annotations

from typing import Any, Optional

from adbygod_api.config import settings
from adbygod_api.core.graph import neo4j_client


class Neo4jGraphService:
    def __init__(self, assessment_id: str):
        self.aid = str(assessment_id)

    def _session(self):
        return neo4j_client.get_driver().session(database=settings.NEO4J_DATABASE)

    async def get_node(self, node_id: str) -> Optional[dict[str, Any]]:
        async with self._session() as s:
            result = await s.run(
                "MATCH (n:Entity {id:$id, assessment_id:$aid}) RETURN n",
                id=node_id, aid=self.aid,
            )
            rec = await result.single()
            return dict(rec["n"]) if rec else None

    async def _lookup(self, prop: str, value: str) -> Optional[str]:
        async with self._session() as s:
            result = await s.run(
                f"MATCH (n:Entity {{assessment_id:$aid}}) WHERE n.{prop} = $v "
                "RETURN n.id AS id LIMIT 1", aid=self.aid, v=value,
            )
            rec = await result.single()
            return rec["id"] if rec else None

    async def lookup_by_sam(self, sam: str) -> Optional[str]:
        return await self._lookup("sam_account_name", sam)

    async def lookup_by_dn(self, dn: str) -> Optional[str]:
        return await self._lookup("distinguished_name", dn)

    async def lookup_by_sid(self, sid: str) -> Optional[str]:
        return await self._lookup("object_sid", sid)
