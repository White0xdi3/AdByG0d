"""Cypher-backed graph queries, scoped per assessment. Replaces ADGraphAnalyzer."""
from __future__ import annotations

import uuid
from typing import Any, Optional

from adbygod_api.config import settings
from adbygod_api.core.graph import neo4j_client
from adbygod_api.core.graph.cypher_mappers import (
    build_attack_path,
    _effective_tier,
    _is_tier0,
    _label_of,
)
from adbygod_api.core.graph.graph_service import (
    AttackPath,
    CONTROL_EDGES,
    CREDENTIAL_EDGES,
)


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
    async def find_shortest_path(
        self, source_id: str, target_id: str, max_hops: int = 12,
    ) -> Optional[AttackPath]:
        # max_hops is an int we control; inline it (variable-length bounds cannot
        # be parameters in Cypher). The all(...) predicate keeps the search inside
        # this assessment (defence-in-depth — projection never bridges assessments).
        # We only take the node *sequence* from shortestPath; _attack_path_from_ids
        # then rebuilds with the highest-risk edge per pair, matching the analyzer
        # (which collapses parallel edges to max risk_weight for scoring).
        cypher = (
            "MATCH (s:Entity {id:$s, assessment_id:$aid}), "
            "(t:Entity {id:$t, assessment_id:$aid}) "
            f"MATCH p = shortestPath((s)-[rels*..{int(max_hops)}]->(t)) "
            "WHERE all(r IN rels WHERE r.assessment_id = $aid) "
            "RETURN [n IN nodes(p) | n.id] AS ids"
        )
        async with self._session() as ses:
            result = await ses.run(cypher, s=source_id, t=target_id, aid=self.aid)
            rec = await result.single()
        if not rec:
            return None
        return await self._attack_path_from_ids(rec["ids"])

    async def find_all_shortest_paths(
        self, source_id: str, target_id: str, max_hops: int = 12, limit: int = 10,
    ) -> list[AttackPath]:
        cypher = (
            "MATCH (s:Entity {id:$s, assessment_id:$aid}), "
            "(t:Entity {id:$t, assessment_id:$aid}) "
            f"MATCH p = allShortestPaths((s)-[rels*..{int(max_hops)}]->(t)) "
            "WHERE all(r IN rels WHERE r.assessment_id = $aid) "
            "RETURN [n IN nodes(p) | n.id] AS ids LIMIT $lim"
        )
        async with self._session() as ses:
            result = await ses.run(
                cypher, s=source_id, t=target_id, aid=self.aid, lim=int(limit),
            )
            id_lists = [rec["ids"] async for rec in result]
        out: list[AttackPath] = []
        for ids in id_lists:
            ap = await self._attack_path_from_ids(ids)
            if ap is not None:
                out.append(ap)
        return out

    async def find_k_shortest_paths(
        self, source_id: str, target_id: str, k: int = 5, max_hops: int = 12,
    ) -> list[AttackPath]:
        """Top-k loopless paths via GDS Yen's, ranked by path_score (desc).

        Mirrors ADGraphAnalyzer.find_k_shortest_paths: collapse parallel edges to
        the highest-risk one (done in _attack_path_from_ids) and weight by
        ``1 - risk_weight`` so Yen's prefers high-risk routes.
        """
        k = int(k)
        gname = "ksp_" + uuid.uuid4().hex
        # Oversample: Yen's returns paths in ascending-weight order, but we drop
        # any exceeding max_hops afterwards. Requesting more than k lets us backfill
        # in weight order (matching the analyzer, which lazily skips too-long paths
        # and keeps going until it has k). Capped to bound cost on large graphs.
        gds_k = min(max(k * 2, k + 5), 64)
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
            "YIELD index, nodeIds "
            "RETURN [n IN nodeIds | gds.util.asNode(n).id] AS ids ORDER BY index"
        )
        id_lists: list[list[str]] = []
        async with self._session() as ses:
            try:
                await (await ses.run(project, g=gname, aid=self.aid)).consume()
                result = await ses.run(
                    yens, g=gname, s=source_id, t=target_id, k=gds_k, aid=self.aid,
                )
                async for rec in result:
                    id_lists.append(rec["ids"])
            finally:
                # Always release the ephemeral in-memory projection.
                await ses.run("CALL gds.graph.drop($g, false)", g=gname)

        # Select the first k paths within max_hops in Yen's (weight) order, then
        # sort those by path_score for display — exactly the analyzer's contract.
        selected: list[AttackPath] = []
        for ids in id_lists:
            if len(ids) - 1 > int(max_hops):
                continue
            ap = await self._attack_path_from_ids(ids)
            if ap is not None:
                selected.append(ap)
            if len(selected) >= k:
                break
        selected.sort(key=lambda p: p.path_score, reverse=True)
        return selected

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
        node_dicts = [dict(n) for n in nodes]
        rel_dicts = [{"type": r.type, **dict(r)} for r in rels]
        return build_attack_path(node_dicts, rel_dicts)

    # ------------------------------------------------------ reachability / views
    async def get_reachable_from(self, source_id: str) -> set[str]:
        """All nodes reachable from source (descendants), mirroring nx.descendants.

        Uses APOC subgraph traversal (visited-tracked BFS) rather than an unbounded
        ``-[*]->`` so it stays efficient on large graphs.
        """
        return await self._reachable(source_id, ">")

    async def get_can_reach(self, target_id: str) -> set[str]:
        """All nodes that can reach target (ancestors), mirroring nx.ancestors."""
        return await self._reachable(target_id, "<")

    async def _reachable(self, node_id: str, direction: str) -> set[str]:
        cypher = (
            "MATCH (start:Entity {id:$id, assessment_id:$aid}) "
            "CALL apoc.path.subgraphNodes(start, "
            "{relationshipFilter:$rf, labelFilter:'+Entity', maxLevel:-1}) YIELD node "
            "WHERE node.assessment_id = $aid AND node.id <> $id "
            "RETURN node.id AS id"
        )
        async with self._session() as ses:
            result = await ses.run(cypher, id=node_id, aid=self.aid, rf=direction)
            return {rec["id"] async for rec in result}

    async def get_neighborhood(
        self, node_id: str, hops: int = 2, max_nodes: int = 200,
    ) -> dict[str, Any]:
        """N-hop subgraph around node_id (both directions), matching the shape
        ADGraphAnalyzer.get_neighborhood returns to the frontend."""
        center_cypher = (
            "MATCH (c:Entity {id:$id, assessment_id:$aid}) "
            "CALL apoc.path.subgraphNodes(c, "
            "{relationshipFilter:'', labelFilter:'+Entity', maxLevel:$hops, limit:$max}) "
            "YIELD node WHERE node.assessment_id = $aid RETURN node"
        )
        async with self._session() as ses:
            nres = await ses.run(
                center_cypher, id=node_id, aid=self.aid,
                hops=int(hops), max=int(max_nodes),
            )
            raw_nodes = [dict(rec["node"]) async for rec in nres]
            if not raw_nodes:
                return {"nodes": [], "edges": []}
            ids = [n["id"] for n in raw_nodes]
            erows = await ses.run(
                "MATCH (s:Entity {assessment_id:$aid})-[r {assessment_id:$aid}]->"
                "(t:Entity {assessment_id:$aid}) "
                "WHERE s.id IN $ids AND t.id IN $ids "
                "RETURN r.id AS id, s.id AS s, t.id AS t, type(r) AS et, "
                "r.risk_weight AS rw, r.edge_confidence AS ec, "
                "r.edge_provenance_type AS ept",
                aid=self.aid, ids=ids,
            )
            edges = [
                {
                    "id": rec["id"], "source": rec["s"], "target": rec["t"],
                    "edge_type": rec["et"],
                    "risk_weight": rec["rw"] if rec["rw"] is not None else 0.5,
                    "edge_confidence": rec["ec"] if rec["ec"] is not None else 1.0,
                    "edge_provenance_type": rec["ept"] or "collected",
                }
                async for rec in erows
            ]
        nodes = [
            {
                "id": n["id"], "label": _label_of(n),
                "entity_type": n.get("entity_type", "UNKNOWN"),
                "tier": _effective_tier(n),
                "is_crown_jewel": bool(n.get("is_crown_jewel")),
                "is_admin_count": bool(n.get("is_admin_count")),
                "community_id": n.get("community_id"),  # set by Louvain (Phase 3)
            }
            for n in raw_nodes
        ]
        return {"nodes": nodes, "edges": edges}

    def _node_view(self, n: dict[str, Any]) -> dict[str, Any]:
        """Full frontend node shape (matches the golden export_for_frontend).

        ``betweenness`` (GDS centrality), ``tier0_reach`` (blast radius),
        ``severity_count`` (findings) and the non-default ``attributes`` fields
        are Phase-3 analytics not yet projected; they are emitted with safe
        defaults so the frontend contract holds.
        """
        return {
            "id": n["id"], "label": _label_of(n),
            "entity_type": n.get("entity_type", "UNKNOWN"),
            "tier": _effective_tier(n),
            "is_crown_jewel": bool(n.get("is_crown_jewel")),
            "is_admin_count": bool(n.get("is_admin_count")),
            "is_tier0": _is_tier0(n),
            "is_enabled": bool(n.get("is_enabled", True)),
            "domain": n.get("domain"),
            "tier0_reach": 0,        # Phase 3: blast radius
            "betweenness": 0.0,      # Phase 3: GDS centrality
            "attributes": {
                "has_spn": bool(n.get("has_spn")),
                "laps_enabled": bool(n.get("laps_enabled")),
                "uac_dont_req_preauth": bool(n.get("uac_dont_req_preauth")),
                "uac_trusted_for_deleg": bool(n.get("uac_trusted_for_deleg")),
                "uac_trusted_to_auth_deleg": bool(n.get("uac_trusted_to_auth_deleg")),
            },
            "severity_count": {},    # Phase 3: finding projection
        }

    async def export_for_frontend(
        self, max_nodes: int = 500, filter_types: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Frontend graph payload: full node/edge shape matching the golden file.

        Node selection here is a simplified, deterministic priority (Tier-0, then
        crown jewels, then label) capped at max_nodes; the analyzer's blast/
        centrality-weighted budgeting is deferred with those Phase-3 metrics.
        """
        node_cypher = (
            "MATCH (n:Entity {assessment_id:$aid}) "
            + ("WHERE n.entity_type IN $ftypes " if filter_types else "")
            + "RETURN n ORDER BY "
            "(CASE WHEN n.tier = 0 OR n.is_crown_jewel THEN 0 ELSE 1 END), "
            "coalesce(n.sam_account_name, n.display_name, n.id) "
            "LIMIT $max"
        )
        async with self._session() as ses:
            nres = await ses.run(
                node_cypher, aid=self.aid,
                ftypes=filter_types or [], max=int(max_nodes),
            )
            raw_nodes = [dict(rec["n"]) async for rec in nres]
            ids = [n["id"] for n in raw_nodes]
            erows = await ses.run(
                "MATCH (s:Entity {assessment_id:$aid})-[r {assessment_id:$aid}]->"
                "(t:Entity {assessment_id:$aid}) "
                "WHERE s.id IN $ids AND t.id IN $ids "
                "RETURN r.id AS id, s.id AS s, t.id AS t, type(r) AS et, "
                "r.risk_weight AS rw, r.edge_confidence AS ec, "
                "r.edge_provenance_type AS ept, r.provenance AS prov",
                aid=self.aid, ids=ids,
            )
            edges = [
                {
                    "id": rec["id"], "source": rec["s"], "target": rec["t"],
                    "edge_type": rec["et"],
                    "risk_weight": round(float(rec["rw"] if rec["rw"] is not None else 0.5), 3),
                    "edge_confidence": rec["ec"] if rec["ec"] is not None else 1.0,
                    "edge_provenance_type": rec["ept"] or "collected",
                    "provenance": rec["prov"] or "",
                    "is_control_edge": rec["et"] in CONTROL_EDGES,
                    "is_credential_edge": rec["et"] in CREDENTIAL_EDGES,
                }
                async for rec in erows
            ]
        nodes = [self._node_view(n) for n in raw_nodes]
        return {
            "nodes": nodes, "edges": edges,
            "node_count": len(nodes), "edge_count": len(edges),
        }
