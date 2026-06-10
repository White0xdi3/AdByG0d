"""Async Neo4j driver singleton + schema bootstrap.

Neo4j is a hard dependency of the graph engine — there is no NetworkX
fallback. The driver is created once at app startup and closed at shutdown
(see main.lifespan). Sessions are short-lived and acquired per query.
"""
from __future__ import annotations

import asyncio
import logging

from neo4j import AsyncGraphDatabase, AsyncDriver

from adbygod_api.config import settings

log = logging.getLogger(__name__)

_driver: AsyncDriver | None = None
# Serialises connect() so concurrent callers can't create two drivers and leak
# a connection pool. connect() is only ever called from a single coroutine
# (app lifespan startup, or one-task-at-a-time prefork Celery), so this lock is
# never *contended* — and asyncio.Lock only binds to a loop on the contended
# acquire path, so it never binds and is safe to reuse across the fresh event
# loops that asyncio.run creates per Celery task. (Do not swap for a
# threading.Lock: it is held across the verify_connectivity() await and a
# threading.Lock across an await can deadlock the event loop.)
_connect_lock: asyncio.Lock = asyncio.Lock()

# Constraints/indexes are idempotent (IF NOT EXISTS). Applied on startup.
SCHEMA_STATEMENTS: list[str] = [
    "CREATE CONSTRAINT entity_id IF NOT EXISTS "
    "FOR (n:Entity) REQUIRE n.id IS UNIQUE",
    "CREATE INDEX entity_assessment IF NOT EXISTS "
    "FOR (n:Entity) ON (n.assessment_id)",
    "CREATE INDEX entity_sid IF NOT EXISTS "
    "FOR (n:Entity) ON (n.object_sid)",
    "CREATE INDEX entity_sam IF NOT EXISTS "
    "FOR (n:Entity) ON (n.sam_account_name)",
    "CREATE INDEX entity_dn IF NOT EXISTS "
    "FOR (n:Entity) ON (n.distinguished_name)",
]


def get_driver() -> AsyncDriver:
    """Return the process-wide async driver. Raises if not connected."""
    if _driver is None:
        raise RuntimeError("Neo4j driver not initialised; call connect() first")
    return _driver


async def connect() -> AsyncDriver:
    """Create the driver and verify connectivity. Idempotent and concurrency-safe."""
    global _driver
    async with _connect_lock:
        if _driver is None:
            _driver = AsyncGraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
            )
            await _driver.verify_connectivity()
            log.info("Neo4j driver connected to %s", settings.NEO4J_URI)
    return _driver


async def close() -> None:
    """Close the driver if open."""
    global _driver
    if _driver is not None:
        await _driver.close()
        _driver = None
        log.info("Neo4j driver closed")


async def ensure_schema() -> None:
    """Apply constraints/indexes (idempotent)."""
    driver = get_driver()
    async with driver.session(database=settings.NEO4J_DATABASE) as session:
        for stmt in SCHEMA_STATEMENTS:
            try:
                await session.run(stmt)
            except Exception:
                log.error("Neo4j schema statement failed: %s", stmt)
                raise
    log.info("Neo4j schema ensured (%d statements)", len(SCHEMA_STATEMENTS))
