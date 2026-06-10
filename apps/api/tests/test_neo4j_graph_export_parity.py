from __future__ import annotations

import json
from pathlib import Path

import pytest

from adbygod_api.config import settings
from adbygod_api.core.graph.neo4j_graph_service import Neo4jGraphService

GOLDEN = Path(__file__).resolve().parents[0] / "fixtures" / "graph_golden"
AID = "33333333-3333-3333-3333-333333333333"

# Node fields backed by Phase-3 analytics not yet projected (GDS betweenness
# centrality and tier-0 blast radius). Everything else is asserted for parity.
_DEFERRED_NODE_FIELDS = {"betweenness", "tier0_reach"}


async def _seed(driver):
    """Seed the golden sample. Edges carry assessment_id (as projection emits)
    but deliberately omit edge_confidence/provenance/edge_provenance_type so the
    test also covers export's defaulting back to the golden values."""
    async with driver.session(database=settings.NEO4J_DATABASE) as s:
        await s.run("MATCH (n {assessment_id:$aid}) DETACH DELETE n", aid=AID)
        await s.run(
            "CREATE (a:Entity {id:'n-alice', assessment_id:$aid, entity_type:'USER', "
            "sam_account_name:'alice'}) "
            "CREATE (h:Entity {id:'n-helpdesk', assessment_id:$aid, entity_type:'GROUP', "
            "sam_account_name:'helpdesk'}) "
            "CREATE (d:Entity {id:'n-da', assessment_id:$aid, entity_type:'GROUP', "
            "sam_account_name:'Domain Admins', tier:0, is_crown_jewel:true}) "
            "CREATE (a)-[:MEMBER_OF {id:'e1', assessment_id:$aid, risk_weight:0.5}]->(h) "
            "CREATE (h)-[:GENERIC_ALL {id:'e2', assessment_id:$aid, risk_weight:1.0}]->(d)",
            aid=AID,
        )


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_export_matches_golden(neo4j_driver):
    await _seed(neo4j_driver)
    got = await Neo4jGraphService(AID).export_for_frontend()
    golden = json.loads((GOLDEN / "export_for_frontend.json").read_text())

    assert got["node_count"] == golden["node_count"] == 3
    assert got["edge_count"] == golden["edge_count"] == 2
    assert {n["id"] for n in got["nodes"]} == {n["id"] for n in golden["nodes"]}

    # Top-level + per-element key shape must equal the frontend contract exactly.
    assert set(got) == set(golden)
    g_node = golden["nodes"][0]
    for n in got["nodes"]:
        assert set(n) == set(g_node)
    g_edge = golden["edges"][0]
    for e in got["edges"]:
        assert set(e) == set(g_edge)

    # Edges are fully derivable from projected props → assert full value parity.
    got_edges = {e["id"]: e for e in got["edges"]}
    for ge in golden["edges"]:
        assert got_edges[ge["id"]] == ge

    # Nodes: assert value parity for every field except the deferred analytics
    # (which are present but default). The deferred keys must still exist.
    golden_nodes = {n["id"]: n for n in golden["nodes"]}
    for n in got["nodes"]:
        assert _DEFERRED_NODE_FIELDS <= set(n)
        gn = golden_nodes[n["id"]]
        stripped = {k: v for k, v in n.items() if k not in _DEFERRED_NODE_FIELDS}
        gn_stripped = {k: v for k, v in gn.items() if k not in _DEFERRED_NODE_FIELDS}
        assert stripped == gn_stripped


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_reachability(neo4j_driver):
    await _seed(neo4j_driver)
    svc = Neo4jGraphService(AID)
    assert await svc.get_reachable_from("n-alice") == {"n-helpdesk", "n-da"}
    assert await svc.get_reachable_from("n-da") == set()
    assert await svc.get_can_reach("n-da") == {"n-alice", "n-helpdesk"}
    assert await svc.get_can_reach("n-alice") == set()


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_reachability_is_assessment_scoped(neo4j_driver):
    await _seed(neo4j_driver)
    other = Neo4jGraphService("44444444-4444-4444-4444-444444444444")
    assert await other.get_reachable_from("n-alice") == set()


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_neighborhood(neo4j_driver):
    await _seed(neo4j_driver)
    svc = Neo4jGraphService(AID)
    nb = await svc.get_neighborhood("n-helpdesk", hops=1)
    ids = {n["id"] for n in nb["nodes"]}
    # 1 hop both directions from helpdesk reaches alice (in) and da (out).
    assert ids == {"n-helpdesk", "n-alice", "n-da"}
    edge_pairs = {(e["source"], e["target"]) for e in nb["edges"]}
    assert edge_pairs == {("n-alice", "n-helpdesk"), ("n-helpdesk", "n-da")}
    # crown-jewel target carries through the neighborhood node view
    da = next(n for n in nb["nodes"] if n["id"] == "n-da")
    assert da["is_crown_jewel"] is True
    assert da["tier"] == 0
    assert "community_id" in da

    # Unknown node yields an empty neighborhood, not an error.
    assert await svc.get_neighborhood("nope") == {"nodes": [], "edges": []}
