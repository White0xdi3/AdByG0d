from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from adbygod_api.config import settings
from adbygod_api.core.graph.neo4j_graph_service import Neo4jGraphService

AID = "11111111-1111-1111-1111-111111111111"
GOLDEN = Path(__file__).resolve().parents[0] / "fixtures" / "graph_golden"


async def _seed(driver):
    """Seed the alice→helpdesk→da sample, mirroring what projection emits.

    Edges carry ``provenance`` and ``edge_confidence`` because projection always
    writes them (defaulting to "" and 1.0); the golden fixtures were frozen from
    that shape, so the seed must match for full-asdict parity.
    """
    async with driver.session(database=settings.NEO4J_DATABASE) as s:
        await s.run("MATCH (n {assessment_id:$aid}) DETACH DELETE n", aid=AID)
        await s.run(
            "CREATE (a:Entity {id:'n-alice', assessment_id:$aid, entity_type:'USER', "
            "sam_account_name:'alice', distinguished_name:'CN=alice', object_sid:'S-1-5-alice'}) "
            "CREATE (h:Entity {id:'n-helpdesk', assessment_id:$aid, entity_type:'GROUP', "
            "sam_account_name:'helpdesk'}) "
            "CREATE (d:Entity {id:'n-da', assessment_id:$aid, entity_type:'GROUP', "
            "sam_account_name:'Domain Admins', tier:0, is_crown_jewel:true}) "
            "CREATE (a)-[:MEMBER_OF {id:'e1', assessment_id:$aid, risk_weight:0.5, "
            "provenance:'', edge_confidence:1.0}]->(h) "
            "CREATE (h)-[:GENERIC_ALL {id:'e2', assessment_id:$aid, risk_weight:1.0, "
            "provenance:'', edge_confidence:1.0}]->(d)",
            aid=AID,
        )


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_lookups_and_get_node(neo4j_driver):
    await _seed(neo4j_driver)
    svc = Neo4jGraphService(AID)
    assert await svc.lookup_by_sam("alice") == "n-alice"
    assert await svc.lookup_by_dn("CN=alice") == "n-alice"
    assert await svc.lookup_by_sid("S-1-5-alice") == "n-alice"
    assert await svc.lookup_by_sam("does-not-exist") is None
    node = await svc.get_node("n-da")
    assert node is not None
    assert node["entity_type"] == "GROUP"
    assert node["tier"] == 0
    # scoping: a different assessment id sees nothing
    assert await Neo4jGraphService("99999999-9999-9999-9999-999999999999").get_node("n-da") is None


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_shortest_path_matches_golden(neo4j_driver):
    await _seed(neo4j_driver)
    svc = Neo4jGraphService(AID)
    got = await svc.find_shortest_path("n-alice", "n-da")
    assert got is not None
    golden = json.loads((GOLDEN / "shortest_path_alice_da.json").read_text())
    assert dataclasses.asdict(got) == golden


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_all_shortest_paths_matches_golden(neo4j_driver):
    await _seed(neo4j_driver)
    svc = Neo4jGraphService(AID)
    got = await svc.find_all_shortest_paths("n-alice", "n-da")
    golden = json.loads((GOLDEN / "all_shortest_paths_alice_da.json").read_text())
    assert [dataclasses.asdict(p) for p in got] == golden


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_k_shortest_paths_matches_golden(neo4j_driver):
    await _seed(neo4j_driver)
    svc = Neo4jGraphService(AID)
    got = await svc.find_k_shortest_paths("n-alice", "n-da")
    golden = json.loads((GOLDEN / "k_shortest_paths_alice_da.json").read_text())
    assert [dataclasses.asdict(p) for p in got] == golden


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_shortest_path_is_assessment_scoped(neo4j_driver):
    await _seed(neo4j_driver)
    # A service bound to a different assessment cannot find the seeded endpoints.
    other = Neo4jGraphService("99999999-9999-9999-9999-999999999999")
    assert await other.find_shortest_path("n-alice", "n-da") is None
    assert await other.find_all_shortest_paths("n-alice", "n-da") == []


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_tier0_by_pattern_without_explicit_tier(neo4j_driver):
    """A high-value target (Tier-0 by SAM pattern) with no explicit tier must

    still score as Tier-0-proximate and report tier 0 on its step — matching the
    analyzer's _build_tier0_index back-propagation. The golden fixtures don't
    cover this (their DA node has tier:0 set), so assert it directly.
    """
    aid = "22222222-2222-2222-2222-222222222222"
    async with neo4j_driver.session(database=settings.NEO4J_DATABASE) as s:
        await s.run("MATCH (n {assessment_id:$aid}) DETACH DELETE n", aid=aid)
        await s.run(
            "CREATE (u:Entity {id:'t-bob', assessment_id:$aid, entity_type:'USER', "
            "sam_account_name:'bob'}) "
            # Tier-0 only via the 'enterprise admins' SAM pattern: no tier, not CJ.
            "CREATE (g:Entity {id:'t-ea', assessment_id:$aid, entity_type:'GROUP', "
            "sam_account_name:'Enterprise Admins'}) "
            "CREATE (u)-[:GENERIC_ALL {id:'te1', assessment_id:$aid, risk_weight:1.0, "
            "provenance:'', edge_confidence:1.0}]->(g)",
            aid=aid,
        )
    svc = Neo4jGraphService(aid)
    ap = await svc.find_shortest_path("t-bob", "t-ea")
    assert ap is not None
    # raw = avg_risk(1.0)*0.40 + (1/1)*0.20 + tier0_prox(1.0)*0.20 = 0.80 → 80.0.
    # Without the tier-0-by-pattern fix this would be 70.0 (tier0_prox 0.5).
    assert ap.path_score == 80.0
    assert ap.risk_level == "HIGH"
    target_step = ap.steps[-1]
    assert target_step.node_id == "t-ea"
    assert target_step.is_crown_jewel is False  # confirms the SAM-pattern branch
    assert target_step.tier == 0  # back-propagated despite no explicit tier


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_no_path_returns_none(neo4j_driver):
    await _seed(neo4j_driver)
    svc = Neo4jGraphService(AID)
    # da → alice has no directed path (edges only run alice → helpdesk → da).
    assert await svc.find_shortest_path("n-da", "n-alice") is None
    assert await svc.find_all_shortest_paths("n-da", "n-alice") == []
