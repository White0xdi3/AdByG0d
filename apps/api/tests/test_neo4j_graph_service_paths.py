from __future__ import annotations

import pytest

from adbygod_api.config import settings
from adbygod_api.core.graph.neo4j_graph_service import Neo4jGraphService

AID = "11111111-1111-1111-1111-111111111111"


async def _seed(driver):
    async with driver.session(database=settings.NEO4J_DATABASE) as s:
        await s.run("MATCH (n {assessment_id:$aid}) DETACH DELETE n", aid=AID)
        await s.run(
            "CREATE (a:Entity {id:'n-alice', assessment_id:$aid, entity_type:'USER', "
            "sam_account_name:'alice', distinguished_name:'CN=alice', object_sid:'S-1-5-alice'}) "
            "CREATE (h:Entity {id:'n-helpdesk', assessment_id:$aid, entity_type:'GROUP', "
            "sam_account_name:'helpdesk'}) "
            "CREATE (d:Entity {id:'n-da', assessment_id:$aid, entity_type:'GROUP', "
            "sam_account_name:'Domain Admins', tier:0, is_crown_jewel:true}) "
            "CREATE (a)-[:MEMBER_OF {id:'e1', risk_weight:0.5}]->(h) "
            "CREATE (h)-[:GENERIC_ALL {id:'e2', risk_weight:1.0}]->(d)",
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
