"""Cypher-backed graph queries, scoped per assessment. Replaces ADGraphAnalyzer."""
from __future__ import annotations

import uuid
from typing import Any, Optional

from adbygod_api.config import settings
from adbygod_api.core.graph import neo4j_client
from adbygod_api.core.graph.cypher_mappers import build_attack_path
from adbygod_api.core.graph.graph_service import AttackPath


class Neo4jGraphService:
    def __init__(self, assessment_id: str):
        self.aid = str(assessment_id)

    def _session(self):
        return neo4j_client.get_driver().session(database=settings.NEO4J_DATABASE)

    # ------------------------------------------------------------------ lookups
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

    # -------------------------------------------------------------- path finding
    def _path_to_attack(self, nodes, rels) -> AttackPath:
        """Map a Cypher path (ordered nodes + relationships) to an AttackPath."""
        node_dicts = [dict(n) for n in nodes]
        rel_dicts = [{"type": r.type, **dict(r)} for r in rels]
        return build_attack_path(node_dicts, rel_dicts)

    async def find_shortest_path(
        self, source_id: str, target_id: str, max_hops: int = 12,
    ) -> Optional[AttackPath]:
        # max_hops is an int we control; inline it (variable-length bounds cannot
        # be parameters in Cypher). The all(...) predicate keeps the search inside
        # this assessment (defence-in-depth — projection never bridges assessments).
        cypher = (
            "MATCH (s:Entity {id:$s, assessment_id:$aid}), "
            "(t:Entity {id:$t, assessment_id:$aid}) "
            f"MATCH p = shortestPath((s)-[rels*..{int(max_hops)}]->(t)) "
            "WHERE all(r IN rels WHERE r.assessment_id = $aid) "
            "RETURN nodes(p) AS ns, relationships(p) AS rs"
        )
        async with self._session() as ses:
            result = await ses.run(cypher, s=source_id, t=target_id, aid=self.aid)
            rec = await result.single()
            return self._path_to_attack(rec["ns"], rec["rs"]) if rec else None

    async def find_all_shortest_paths(
        self, source_id: str, target_id: str, max_hops: int = 12, limit: int = 10,
    ) -> list[AttackPath]:
        cypher = (
            "MATCH (s:Entity {id:$s, assessment_id:$aid}), "
            "(t:Entity {id:$t, assessment_id:$aid}) "
            f"MATCH p = allShortestPaths((s)-[rels*..{int(max_hops)}]->(t)) "
            "WHERE all(r IN rels WHERE r.assessment_id = $aid) "
            "RETURN nodes(p) AS ns, relationships(p) AS rs LIMIT $lim"
        )
        out: list[AttackPath] = []
        async with self._session() as ses:
            result = await ses.run(
                cypher, s=source_id, t=target_id, aid=self.aid, lim=int(limit),
            )
            async for rec in result:
                out.append(self._path_to_attack(rec["ns"], rec["rs"]))
        return out

    async def find_k_shortest_paths(
        self, source_id: str, target_id: str, k: int = 5, max_hops: int = 12,
    ) -> list[AttackPath]:
        """Top-k loopless paths via GDS Yen's, ranked by path_score (desc).

        Mirrors ADGraphAnalyzer.find_k_shortest_paths: collapse parallel edges to
        the highest-risk one (done in _attack_path_from_ids) and weight by
        ``1 - risk_weight`` so Yen's prefers high-risk routes.
        """
        gname = "ksp_" + uuid.uuid4().hex
        project = (
            "MATCH (s:Entity {assessment_id:$aid})-[r {assessment_id:$aid}]->"
            "(t:Entity {assessment_id:$aid}) "
            "WITH s, t, (1.0 - coalesce(r.risk_weight, 0.5)) AS w "
            "RETURN gds.graph.project($g, s, t, {relationshipProperties: {w: w}}) AS g"
        )
        yens = (
            "MATCH (s:Entity {id:$s, assessment_id:$aid}), "
            "(t:Entity {id:$t, assessment_id:$aid}) "
            "CALL gds.shortestPath.yens.stream($g, "
            "{sourceNode: s, targetNode: t, k: $k, relationshipWeightProperty: 'w'}) "
            "YIELD nodeIds "
            "RETURN [n IN nodeIds | gds.util.asNode(n).id] AS ids"
        )
        id_lists: list[list[str]] = []
        async with self._session() as ses:
            try:
                await (await ses.run(project, g=gname, aid=self.aid)).consume()
                result = await ses.run(
                    yens, g=gname, s=source_id, t=target_id, k=int(k), aid=self.aid,
                )
                async for rec in result:
                    id_lists.append(rec["ids"])
            finally:
                # Always release the ephemeral in-memory projection.
                await ses.run("CALL gds.graph.drop($g, false)", g=gname)

        paths: list[AttackPath] = []
        for ids in id_lists:
            if len(ids) - 1 > int(max_hops):
                continue
            ap = await self._attack_path_from_ids(ids)
            if ap is not None:
                paths.append(ap)
        paths.sort(key=lambda p: p.path_score, reverse=True)
        return paths[: int(k)]

    async def _attack_path_from_ids(self, ids: list[str]) -> Optional[AttackPath]:
        """Rebuild an AttackPath from an ordered list of node ids (used by GDS).

        Fetches the ordered nodes and, for each consecutive pair, the
        highest-risk relationship — matching the analyzer's DiGraph collapse.
        """
        if len(ids) < 2:
            return None
        nodes_cypher = (
            "UNWIND range(0, size($ids)-1) AS i "
            "MATCH (n:Entity {id:$ids[i], assessment_id:$aid}) "
            "RETURN n ORDER BY i"
        )
        rels_cypher = (
            "UNWIND range(0, size($ids)-2) AS i "
            "MATCH (a:Entity {id:$ids[i], assessment_id:$aid})"
            "-[r {assessment_id:$aid}]->(b:Entity {id:$ids[i+1], assessment_id:$aid}) "
            "WITH i, r ORDER BY r.risk_weight DESC "
            "WITH i, collect(r)[0] AS r "
            "RETURN r ORDER BY i"
        )
        async with self._session() as ses:
            nres = await ses.run(nodes_cypher, ids=ids, aid=self.aid)
            nodes = [rec["n"] async for rec in nres]
            rres = await ses.run(rels_cypher, ids=ids, aid=self.aid)
            rels = [rec["r"] async for rec in rres]
        if len(nodes) != len(ids) or len(rels) != len(ids) - 1:
            return None
        return self._path_to_attack(nodes, rels)
