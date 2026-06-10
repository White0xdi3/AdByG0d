"""Session-scoped Neo4j (+GDS+APOC) test container and a connected driver fixture.

Graph tests require Neo4j. If Docker/testcontainers is unavailable, tests
marked @pytest.mark.neo4j are skipped (the rest of the suite is unaffected).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(scope="session")
def neo4j_container():
    try:
        from testcontainers.neo4j import Neo4jContainer
    except Exception as exc:
        pytest.skip(f"testcontainers not available: {exc}")
    container = (
        Neo4jContainer("neo4j:5-community")
        .with_env("NEO4J_PLUGINS", '["graph-data-science","apoc"]')
        .with_env("NEO4J_dbms_security_procedures_unrestricted", "gds.*,apoc.*")
    )
    try:
        container.start()
    except Exception as exc:
        pytest.skip(f"could not start Neo4j container (Docker?): {exc}")
    yield container
    container.stop()


@pytest.fixture()
async def neo4j_driver(neo4j_container):
    """Point settings at the container, connect the client, clean DB per test.

    Async, function-scoped fixture so it shares the per-function event loop
    that pytest-asyncio creates for the (also function-scoped) test, avoiding
    'driver attached to a different loop' errors that occur with asyncio.run().
    NOTE: if this fixture is ever made session-scoped, the driver must also be
    created under a session-scoped loop (set asyncio loop_scope to match) or
    the wrong-loop bug returns.

    Mutations to the global ``settings`` singleton are restored on teardown so
    later tests in the session don't inherit the container's ephemeral address.
    """
    import adbygod_api.config as config
    from adbygod_api.core.graph import neo4j_client

    orig = (
        config.settings.NEO4J_URI,
        config.settings.NEO4J_USER,
        config.settings.NEO4J_PASSWORD,
        config.settings.NEO4J_DATABASE,
    )

    bolt = neo4j_container.get_connection_url()  # bolt://host:port
    config.settings.NEO4J_URI = bolt
    config.settings.NEO4J_USER = neo4j_container.username
    config.settings.NEO4J_PASSWORD = neo4j_container.password
    config.settings.NEO4J_DATABASE = "neo4j"

    await neo4j_client.close()
    await neo4j_client.connect()
    async with neo4j_client.get_driver().session(database=config.settings.NEO4J_DATABASE) as s:
        await s.run("MATCH (n) DETACH DELETE n")
    await neo4j_client.ensure_schema()

    try:
        yield neo4j_client.get_driver()
    finally:
        await neo4j_client.close()
        (
            config.settings.NEO4J_URI,
            config.settings.NEO4J_USER,
            config.settings.NEO4J_PASSWORD,
            config.settings.NEO4J_DATABASE,
        ) = orig
