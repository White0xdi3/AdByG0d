"""Integration test: Postgres→Neo4j projection service.

Uses a real Neo4j container (via neo4j_driver fixture) and an in-memory
SQLite database to verify reproject_assessment is correct and idempotent.
"""
from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import adbygod_api.config as config
import adbygod_api.models as models
from adbygod_api.config import settings
from adbygod_api.core.graph import projection


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _setup_sqlite():
    """Create a fresh in-memory SQLite DB and return (engine, session_maker)."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    return engine, session_maker


async def _seed(session_maker) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """Create Assessment + 2 Entities + 1 MEMBER_OF edge; return (aid, uid, gid)."""
    async with session_maker() as db:
        assessment = models.Assessment(
            name="Test Assessment",
            domain="corp.local",
            workspace_id=None,
            created_by=None,
            status=models.AssessmentStatus.PENDING,
            exposure_score=0.0,
            modules_run=[],
            stats={},
        )
        db.add(assessment)
        await db.flush()
        aid = assessment.id

        alice = models.Entity(
            assessment_id=aid,
            entity_type=models.EntityType.USER,
            sam_account_name="alice",
            display_name="alice",
            is_enabled=True,
            is_admin_count=False,
            is_sensitive=False,
            is_protected_user=False,
            tier=None,
            is_crown_jewel=False,
            business_tags=[],
            attributes={},
        )
        admins = models.Entity(
            assessment_id=aid,
            entity_type=models.EntityType.GROUP,
            sam_account_name="admins",
            display_name="admins",
            is_enabled=True,
            is_admin_count=True,
            is_sensitive=False,
            is_protected_user=False,
            tier=0,
            is_crown_jewel=False,
            business_tags=[],
            attributes={},
        )
        db.add(alice)
        db.add(admins)
        await db.flush()

        edge = models.GraphEdge(
            assessment_id=aid,
            source_id=alice.id,
            target_id=admins.id,
            edge_type=models.EdgeType.MEMBER_OF,
            risk_weight=0.9,
            attributes={},
        )
        db.add(edge)
        await db.commit()

        return aid, alice.id, admins.id


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_reproject_assessment(neo4j_driver):
    """Full round-trip: seed SQLite → project → verify Neo4j → re-project → idempotent."""
    # EncryptedJSON columns on Assessment require a non-empty SECRET_KEY.
    _orig_secret = config.settings.SECRET_KEY
    config.settings.SECRET_KEY = "test-secret-key-with-sufficient-length-1234567890"
    engine, session_maker = await _setup_sqlite()
    try:
        aid, alice_id, admins_id = await _seed(session_maker)
        aid_str = str(aid)

        # --- First projection ---
        async with session_maker() as db:
            result = await projection.reproject_assessment(db, aid_str)

        assert result == {"nodes": 2, "edges": 1}, f"unexpected result: {result}"

        # --- Verify nodes in Neo4j ---
        async with neo4j_driver.session(database=settings.NEO4J_DATABASE) as neo_session:
            node_res = await neo_session.run(
                "MATCH (n:Entity {assessment_id: $aid}) RETURN count(n) AS cnt",
                aid=aid_str,
            )
            record = await node_res.single()
            assert record["cnt"] == 2, f"expected 2 nodes, got {record['cnt']}"

            # --- Verify the MEMBER_OF edge ---
            edge_res = await neo_session.run(
                "MATCH (:Entity)-[r:MEMBER_OF]->(:Entity {assessment_id: $aid}) RETURN count(r) AS cnt",
                aid=aid_str,
            )
            edge_record = await edge_res.single()
            assert edge_record["cnt"] == 1, f"expected 1 MEMBER_OF edge, got {edge_record['cnt']}"

        # --- Idempotency: re-project and assert no duplicates ---
        async with session_maker() as db:
            result2 = await projection.reproject_assessment(db, aid_str)

        assert result2 == {"nodes": 2, "edges": 1}, f"unexpected idempotency result: {result2}"

        async with neo4j_driver.session(database=settings.NEO4J_DATABASE) as neo_session:
            node_res2 = await neo_session.run(
                "MATCH (n:Entity {assessment_id: $aid}) RETURN count(n) AS cnt",
                aid=aid_str,
            )
            record2 = await node_res2.single()
            assert record2["cnt"] == 2, (
                f"idempotency failed: expected 2 nodes after re-projection, got {record2['cnt']}"
            )

            edge_res2 = await neo_session.run(
                "MATCH (:Entity)-[r:MEMBER_OF]->(:Entity {assessment_id: $aid}) RETURN count(r) AS cnt",
                aid=aid_str,
            )
            edge_record2 = await edge_res2.single()
            assert edge_record2["cnt"] == 1, (
                f"idempotency failed: expected 1 edge after re-projection, got {edge_record2['cnt']}"
            )

    finally:
        config.settings.SECRET_KEY = _orig_secret
        await engine.dispose()
