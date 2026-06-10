# Neo4j Graph Engine — Foundation Implementation Plan (Phases 0–2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up Neo4j (+GDS) as the graph engine for AdByG0d and make the existing Graph Explorer / Attack Paths routes serve traversal results from Neo4j instead of in-memory NetworkX, with Postgres remaining the system-of-record.

**Architecture:** Hybrid. Postgres is authoritative for entities/edges (ingest unchanged). After ingest, each assessment's subgraph is **projected** into Neo4j (batched `UNWIND`). A single `Neo4jGraphService` answers path/reachability/export queries via Cypher, scoped by `assessment_id`. There is **no NetworkX runtime fallback** — Neo4j runs in dev and prod alike. The retired NetworkX `ADGraphAnalyzer` is used only once, offline, to freeze golden test fixtures.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0 async, Celery + Redis (existing), Neo4j 5 Community + Graph Data Science (GDS) plugin, `neo4j` async Python driver, pytest + testcontainers.

**Scope note:** This plan delivers spec Phases 0–2 (the merge gate). Spec Phases 3–6 (GDS analytics, detectors, simulation, NetworkX deletion) are separate follow-on plans written once these Cypher/projection patterns are proven against a live Neo4j. Spec: `docs/superpowers/specs/2026-06-10-neo4j-graph-engine-design.md`.

---

## File Structure

**Created:**
- `apps/api/src/adbygod_api/core/graph/neo4j_client.py` — async driver singleton + lifecycle + schema bootstrap.
- `apps/api/src/adbygod_api/core/graph/projection.py` — Postgres→Neo4j projection (delete-scope + batched UNWIND).
- `apps/api/src/adbygod_api/core/graph/neo4j_graph_service.py` — Cypher-backed query service (paths, reachability, neighborhood, export, lookups).
- `apps/api/src/adbygod_api/core/graph/cypher_mappers.py` — pure functions mapping Cypher rows ↔ `AttackPath`/frontend dicts (reuse the existing dataclasses).
- `apps/api/src/adbygod_api/core/tasks/graph_projection.py` — Celery task wrapping `projection.reproject_assessment`.
- `apps/api/src/adbygod_api/models_neo4j_state.py` *(or extend `models.py`)* — `GraphProjectionState` table (`last_projected_at`, counts).
- `docker-compose.dev.yml` — lightweight dev Neo4j (+GDS).
- `apps/api/tests/neo4j_fixtures.py` — testcontainers Neo4j fixture + helpers.
- `apps/api/tests/test_neo4j_client.py`, `test_graph_projection.py`, `test_neo4j_graph_service_paths.py`, `test_neo4j_graph_export_parity.py`, `test_graph_route_neo4j.py`.
- `apps/api/tests/fixtures/graph_golden/` — frozen JSON fixtures generated from the NetworkX reference.
- `apps/api/scripts/generate_graph_golden.py` — one-shot golden-fixture generator (dev tool, not shipped runtime).

**Modified:**
- `apps/api/requirements.txt` — add `neo4j`, `testcontainers[neo4j]`.
- `apps/api/src/adbygod_api/config.py` — add `NEO4J_*`, `GRAPH_QUERY_TIMEOUT_SECONDS`, `GRAPH_PROJECT_BATCH_SIZE`.
- `apps/api/src/adbygod_api/main.py` — connect/close Neo4j + ensure schema in `lifespan`.
- `apps/api/src/adbygod_api/core/celery_app.py` — register the projection task module.
- `apps/api/src/adbygod_api/routes/graph.py` — replace `_get_analyzer`/`_graph_cache` with `_get_service` (Neo4j); add reproject endpoint + projection state.
- `apps/api/src/adbygod_api/routes/ingest.py:1399` — enqueue projection after commit.
- `docker-compose.yml`, `docker-compose.prod.yml`, `.env.docker.example` — add `neo4j` service + env.
- `apps/api/tests/conftest.py` — expose the Neo4j fixture to route tests.

---

# Phase 0 — Scaffolding

### Task 1: Dependencies + config settings

**Files:**
- Modify: `apps/api/requirements.txt`
- Modify: `apps/api/src/adbygod_api/config.py`
- Test: `apps/api/tests/test_neo4j_config.py`

- [ ] **Step 1: Write the failing test**

```python
# apps/api/tests/test_neo4j_config.py
from __future__ import annotations
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adbygod_api.config import Settings


def test_neo4j_settings_have_defaults():
    s = Settings()
    assert s.NEO4J_URI == "bolt://localhost:7687"
    assert s.NEO4J_USER == "neo4j"
    assert s.NEO4J_DATABASE == "neo4j"
    assert s.GRAPH_QUERY_TIMEOUT_SECONDS == 30
    assert s.GRAPH_PROJECT_BATCH_SIZE == 10000


def test_neo4j_settings_env_override(monkeypatch):
    monkeypatch.setenv("NEO4J_URI", "bolt://neo4j:7687")
    monkeypatch.setenv("NEO4J_PASSWORD", "s3cret")
    s = Settings()
    assert s.NEO4J_URI == "bolt://neo4j:7687"
    assert s.NEO4J_PASSWORD == "s3cret"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -m pytest tests/test_neo4j_config.py -v`
Expected: FAIL — `AttributeError: 'Settings' object has no attribute 'NEO4J_URI'`.

- [ ] **Step 3: Add settings**

In `apps/api/src/adbygod_api/config.py`, inside `class Settings(BaseSettings)` (alongside `REDIS_URL`, around line 35), add:

```python
    # Graph engine (Neo4j) — required in all environments, no NetworkX fallback
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = ""
    NEO4J_DATABASE: str = "neo4j"
    GRAPH_QUERY_TIMEOUT_SECONDS: int = 30
    GRAPH_PROJECT_BATCH_SIZE: int = 10000
```

- [ ] **Step 4: Add dependencies**

In `apps/api/requirements.txt`, under the `# Analysis / graph` section, add:

```
neo4j==5.27.0
```

Under a `# Test infra` section (create if absent), add:

```
testcontainers[neo4j]==4.9.0
```

Then install: `cd apps/api && .venv/bin/pip install neo4j==5.27.0 "testcontainers[neo4j]==4.9.0"`

- [ ] **Step 5: Run test to verify it passes**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -m pytest tests/test_neo4j_config.py -v`
Expected: PASS (2 passed).

- [ ] **Step 6: Commit**

```bash
git add apps/api/requirements.txt apps/api/src/adbygod_api/config.py apps/api/tests/test_neo4j_config.py
git commit -m "feat(graph): add Neo4j config settings and driver deps"
```

---

### Task 2: Neo4j async client + lifecycle

**Files:**
- Create: `apps/api/src/adbygod_api/core/graph/neo4j_client.py`
- Test: `apps/api/tests/test_neo4j_client.py`

- [ ] **Step 1: Write the client module**

```python
# apps/api/src/adbygod_api/core/graph/neo4j_client.py
"""Async Neo4j driver singleton + schema bootstrap.

Neo4j is a hard dependency of the graph engine — there is no NetworkX
fallback. The driver is created once at app startup and closed at shutdown
(see main.lifespan). Sessions are short-lived and acquired per query.
"""
from __future__ import annotations

import logging
from typing import Optional

from neo4j import AsyncGraphDatabase, AsyncDriver

from adbygod_api.config import settings

log = logging.getLogger(__name__)

_driver: Optional[AsyncDriver] = None

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
    """Create the driver and verify connectivity. Idempotent."""
    global _driver
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


async def ensure_schema() -> None:
    """Apply constraints/indexes (idempotent)."""
    driver = get_driver()
    async with driver.session(database=settings.NEO4J_DATABASE) as session:
        for stmt in SCHEMA_STATEMENTS:
            await session.run(stmt)
    log.info("Neo4j schema ensured (%d statements)", len(SCHEMA_STATEMENTS))
```

- [ ] **Step 2: Write the failing test** (requires the Neo4j fixture from Task 5 — write the test now, it will be collected/skipped until the fixture lands; mark with the shared marker)

```python
# apps/api/tests/test_neo4j_client.py
from __future__ import annotations
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import pytest

from adbygod_api.core.graph import neo4j_client


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_ensure_schema_is_idempotent(neo4j_driver):
    # neo4j_driver fixture (Task 5) has already called connect()
    await neo4j_client.ensure_schema()
    await neo4j_client.ensure_schema()  # second call must not raise
    async with neo4j_client.get_driver().session() as s:
        result = await s.run("SHOW CONSTRAINTS YIELD name RETURN count(*) AS n")
        rec = await result.single()
        assert rec["n"] >= 1
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -m pytest tests/test_neo4j_client.py -v`
Expected: FAIL/ERROR — fixture `neo4j_driver` not found (provided in Task 5). This is expected; the test goes green after Task 5.

- [ ] **Step 4: Commit the client (test stays red until Task 5)**

```bash
git add apps/api/src/adbygod_api/core/graph/neo4j_client.py apps/api/tests/test_neo4j_client.py
git commit -m "feat(graph): add Neo4j async client, lifecycle, and schema bootstrap"
```

---

### Task 3: Wire driver lifecycle into FastAPI lifespan

**Files:**
- Modify: `apps/api/src/adbygod_api/main.py:65-71`

- [ ] **Step 1: Read the current lifespan**

Run: `sed -n '63,75p' apps/api/src/adbygod_api/main.py`
Expected: shows the `@asynccontextmanager async def lifespan(...)` that runs `Base.metadata.create_all`.

- [ ] **Step 2: Add Neo4j connect/schema on startup and close on shutdown**

Edit `apps/api/src/adbygod_api/main.py`. Add import near the other `adbygod_api` imports:

```python
from adbygod_api.core.graph import neo4j_client
```

In `lifespan`, after the existing `create_all` block and before `yield`, add:

```python
        await neo4j_client.connect()
        await neo4j_client.ensure_schema()
```

After `yield` (shutdown), add:

```python
    await neo4j_client.close()
```

(Match the existing indentation/try structure in `lifespan`.)

- [ ] **Step 3: Verify import + app construction still works**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -c "import adbygod_api.main as m; print(type(m.app).__name__)"`
Expected: prints `FastAPI` with no import error. (Connectivity is attempted only when the app actually starts; importing the module must not connect.)

- [ ] **Step 4: Commit**

```bash
git add apps/api/src/adbygod_api/main.py
git commit -m "feat(graph): connect/close Neo4j in app lifespan"
```

---

### Task 4: docker-compose services (dev + prod) + env example

**Files:**
- Create: `docker-compose.dev.yml`
- Modify: `docker-compose.yml`, `docker-compose.prod.yml`, `.env.docker.example`

- [ ] **Step 1: Add the `neo4j` service to `docker-compose.yml`**

Add a service (sibling of `redis`), and add `neo4j` to `api` and `worker` `depends_on`:

```yaml
  neo4j:
    image: neo4j:5-community
    environment:
      NEO4J_AUTH: neo4j/${NEO4J_PASSWORD:-adbygod_dev}
      NEO4J_PLUGINS: '["graph-data-science"]'
      NEO4J_dbms_security_procedures_unrestricted: gds.*
      NEO4J_server_memory_heap_max__size: 1G
      NEO4J_server_memory_pagecache_size: 512M
    ports:
      - "7474:7474"
      - "7687:7687"
    volumes:
      - neo4j_data:/data
    healthcheck:
      test: ["CMD", "cypher-shell", "-u", "neo4j", "-p", "${NEO4J_PASSWORD:-adbygod_dev}", "RETURN 1"]
      interval: 10s
      timeout: 5s
      retries: 10
```

Add `neo4j_data:` under the top-level `volumes:` block (next to `api_data`).

- [ ] **Step 2: Create `docker-compose.dev.yml`**

```yaml
# Lightweight dev stack: Neo4j (+GDS) so local dev runs the same graph
# code path as prod. Compose with the base file:
#   docker compose -f docker-compose.yml -f docker-compose.dev.yml up neo4j redis
services:
  neo4j:
    image: neo4j:5-community
    environment:
      NEO4J_AUTH: neo4j/${NEO4J_PASSWORD:-adbygod_dev}
      NEO4J_PLUGINS: '["graph-data-science"]'
      NEO4J_dbms_security_procedures_unrestricted: gds.*
      NEO4J_server_memory_heap_max__size: 512M
      NEO4J_server_memory_pagecache_size: 256M
    ports:
      - "7474:7474"
      - "7687:7687"
```

- [ ] **Step 3: Mirror the service into `docker-compose.prod.yml`**

Add the same `neo4j` service to `docker-compose.prod.yml` with production memory sizing (e.g. `NEO4J_server_memory_heap_max__size: 4G`, `NEO4J_server_memory_pagecache_size: 4G`), a `restart: unless-stopped` policy, and `NEO4J_AUTH: neo4j/${NEO4J_PASSWORD:?set NEO4J_PASSWORD}` so prod refuses to start without a password. Add `neo4j` to prod `api`/`worker` `depends_on` with `condition: service_healthy`.

- [ ] **Step 4: Document env vars**

Append to `.env.docker.example`:

```
# Graph engine (Neo4j) — required, no fallback
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=change_me
NEO4J_DATABASE=neo4j
```

- [ ] **Step 5: Validate compose files parse**

Run: `docker compose -f docker-compose.yml config >/dev/null && docker compose -f docker-compose.yml -f docker-compose.dev.yml config >/dev/null && echo OK`
Expected: prints `OK` (no YAML/compose schema errors).

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yml docker-compose.dev.yml docker-compose.prod.yml .env.docker.example
git commit -m "feat(graph): add Neo4j (+GDS) services to dev and prod compose"
```

---

### Task 5: Test harness — testcontainers Neo4j fixture

**Files:**
- Create: `apps/api/tests/neo4j_fixtures.py`
- Modify: `apps/api/tests/conftest.py`
- Modify: `apps/api/pytest.ini` (or `pyproject.toml`/`setup.cfg`) — register the `neo4j` marker and `asyncio_mode`

- [ ] **Step 1: Write the fixture module**

```python
# apps/api/tests/neo4j_fixtures.py
"""Session-scoped Neo4j (+GDS) test container and a connected driver fixture.

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
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"testcontainers not available: {exc}")
    container = (
        Neo4jContainer("neo4j:5-community")
        .with_env("NEO4J_PLUGINS", '["graph-data-science"]')
        .with_env("NEO4J_dbms_security_procedures_unrestricted", "gds.*")
    )
    try:
        container.start()
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"could not start Neo4j container (Docker?): {exc}")
    yield container
    container.stop()


@pytest.fixture()
def neo4j_driver(neo4j_container, monkeypatch):
    """Point settings at the container, connect the client, clean DB per test."""
    import adbygod_api.config as config
    from adbygod_api.core.graph import neo4j_client
    import asyncio

    bolt = neo4j_container.get_connection_url()  # bolt://host:port
    config.settings.NEO4J_URI = bolt
    config.settings.NEO4J_USER = "neo4j"
    config.settings.NEO4J_PASSWORD = neo4j_container.password
    config.settings.NEO4J_DATABASE = "neo4j"

    async def _up():
        await neo4j_client.close()
        await neo4j_client.connect()
        async with neo4j_client.get_driver().session() as s:
            await s.run("MATCH (n) DETACH DELETE n")
        await neo4j_client.ensure_schema()

    asyncio.run(_up())
    yield neo4j_client.get_driver()
    asyncio.run(neo4j_client.close())
```

- [ ] **Step 2: Re-export the fixtures from conftest**

At the end of `apps/api/tests/conftest.py`, add:

```python
from tests.neo4j_fixtures import neo4j_container, neo4j_driver  # noqa: E402,F401
```

(If `tests` is not importable as a package, instead add `pytest_plugins = ["tests.neo4j_fixtures"]` near the top of `conftest.py`.)

- [ ] **Step 3: Register the marker and asyncio mode**

Ensure `apps/api/pytest.ini` (create if missing) contains:

```ini
[pytest]
markers =
    neo4j: test requires a running Neo4j container
asyncio_mode = auto
```

Confirm `pytest-asyncio` is installed (`cd apps/api && .venv/bin/pip show pytest-asyncio` — add `pytest-asyncio` to requirements test section if absent).

- [ ] **Step 4: Run the Task 2 client test — now it should pass (or skip cleanly)**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -m pytest tests/test_neo4j_client.py -v`
Expected: PASS if Docker is available; otherwise `SKIPPED` (never ERROR/collection failure).

- [ ] **Step 5: Commit**

```bash
git add apps/api/tests/neo4j_fixtures.py apps/api/tests/conftest.py apps/api/pytest.ini
git commit -m "test(graph): add testcontainers Neo4j fixture and neo4j marker"
```

---

# Phase 1 — Projection (Postgres → Neo4j)

### Task 6: Projection service

**Files:**
- Create: `apps/api/src/adbygod_api/core/graph/projection.py`
- Test: `apps/api/tests/test_graph_projection.py`

Projects one assessment's entities/edges from Postgres into Neo4j: delete that assessment's nodes/rels, then bulk-load in batches. Node label `Entity` + a per-type secondary label; relationship type = `edge_type`.

- [ ] **Step 1: Write the projection module**

```python
# apps/api/src/adbygod_api/core/graph/projection.py
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


_DELETE_CYPHER = (
    "MATCH (n:Entity {assessment_id: $aid}) DETACH DELETE n"
)

# entity_type is set as a dynamic second label via apoc.create.addLabels.
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
    t
) YIELD rel
RETURN count(rel)
"""


async def reproject_assessment(db: AsyncSession, assessment_id: str) -> dict[str, int]:
    """Rebuild one assessment's Neo4j subgraph from Postgres. Idempotent."""
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
```

> **Note on `apoc`:** `apoc.create.addLabels` / `apoc.merge.relationship` require the APOC plugin. Add `apoc` to `NEO4J_PLUGINS` (`'["graph-data-science","apoc"]'`) in all three compose files and the test fixture. If you prefer zero-APOC, replace node-label setting with a fixed `:Entity` label only (defer per-type labels to Phase 2) and the edge load with one `MERGE` per distinct `edge_type` value — but APOC is the simpler path and is bundled with Neo4j.

- [ ] **Step 2: Update `NEO4J_PLUGINS` to include apoc**

In `docker-compose.yml`, `docker-compose.dev.yml`, `docker-compose.prod.yml`, and `tests/neo4j_fixtures.py`, change `'["graph-data-science"]'` → `'["graph-data-science","apoc"]'` and add `NEO4J_dbms_security_procedures_unrestricted: gds.*,apoc.*` (fixture: `.with_env(... "gds.*,apoc.*")`).

- [ ] **Step 3: Write the failing test**

```python
# apps/api/tests/test_graph_projection.py
from __future__ import annotations
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from adbygod_api import models
from adbygod_api.config import settings
from adbygod_api.core.graph import projection


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_reproject_loads_nodes_and_edges(neo4j_driver, tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/p.db")
    async with engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    sm = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    aid = uuid.uuid4()
    async with sm() as db:
        db.add(models.Assessment(id=aid, name="t", domain="d", workspace_id=None,
                                 modules_run=[], stats={}))
        a = models.Entity(id=uuid.uuid4(), assessment_id=aid,
                          entity_type=models.EntityType.USER, sam_account_name="alice",
                          attributes={})
        b = models.Entity(id=uuid.uuid4(), assessment_id=aid,
                          entity_type=models.EntityType.GROUP, sam_account_name="admins",
                          attributes={})
        db.add_all([a, b])
        await db.flush()
        db.add(models.GraphEdge(id=uuid.uuid4(), assessment_id=aid,
                                source_id=a.id, target_id=b.id,
                                edge_type=models.EdgeType.MEMBER_OF,
                                risk_weight=0.5, attributes={}))
        await db.commit()

        counts = await projection.reproject_assessment(db, str(aid))
    assert counts == {"nodes": 2, "edges": 1}

    async with neo4j_driver.session(database=settings.NEO4J_DATABASE) as s:
        n = await (await s.run(
            "MATCH (n:Entity {assessment_id:$aid}) RETURN count(n) AS n", aid=str(aid)
        )).single()
        r = await (await s.run(
            "MATCH (:Entity {assessment_id:$aid})-[r:MEMBER_OF]->() RETURN count(r) AS n",
            aid=str(aid),
        )).single()
    assert n["n"] == 2 and r["n"] == 1

    # Idempotency: a second projection yields identical counts (no duplicates).
    async with sm() as db:
        await projection.reproject_assessment(db, str(aid))
    async with neo4j_driver.session(database=settings.NEO4J_DATABASE) as s:
        n2 = await (await s.run(
            "MATCH (n:Entity {assessment_id:$aid}) RETURN count(n) AS n", aid=str(aid)
        )).single()
    assert n2["n"] == 2
    await engine.dispose()
```

- [ ] **Step 4: Run test to verify it fails, then passes**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -m pytest tests/test_graph_projection.py -v`
Expected first run: FAIL/ERROR (module or behavior incomplete). Iterate the Cypher/module until it PASSES (or SKIPS without Docker).

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/adbygod_api/core/graph/projection.py apps/api/tests/test_graph_projection.py docker-compose*.yml apps/api/tests/neo4j_fixtures.py
git commit -m "feat(graph): project assessments from Postgres into Neo4j (idempotent)"
```

---

### Task 7: Celery projection task

**Files:**
- Create: `apps/api/src/adbygod_api/core/tasks/graph_projection.py`
- Modify: `apps/api/src/adbygod_api/core/celery_app.py` (add to `imports`)
- Test: `apps/api/tests/test_graph_projection_task.py`

- [ ] **Step 1: Write the task**

```python
# apps/api/src/adbygod_api/core/tasks/graph_projection.py
"""Celery task: (re)project an assessment's graph into Neo4j after ingest."""
from __future__ import annotations

import asyncio
import logging

from adbygod_api.core.celery_app import celery_app
from adbygod_api.core.graph import neo4j_client, projection
from adbygod_api.database import AsyncSessionLocal

log = logging.getLogger(__name__)


async def _run(assessment_id: str) -> dict[str, int]:
    await neo4j_client.connect()
    async with AsyncSessionLocal() as db:
        return await projection.reproject_assessment(db, assessment_id)


@celery_app.task(name="graph.project_assessment", queue="offensive_jobs")
def project_assessment(assessment_id: str) -> dict[str, int]:
    return asyncio.run(_run(assessment_id))
```

- [ ] **Step 2: Register the task module for autodiscovery**

In `apps/api/src/adbygod_api/core/celery_app.py`, add `"adbygod_api.core.tasks.graph_projection"` to the `"imports"` list.

- [ ] **Step 3: Write the failing test (eager mode, mock projection)**

```python
# apps/api/tests/test_graph_projection_task.py
from __future__ import annotations
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import asyncio
import pytest

from adbygod_api.core.tasks import graph_projection


def test_task_invokes_projection(monkeypatch):
    calls = {}

    async def fake_connect():
        return None

    async def fake_reproject(db, aid):
        calls["aid"] = aid
        return {"nodes": 3, "edges": 2}

    monkeypatch.setattr(graph_projection.neo4j_client, "connect", fake_connect)
    monkeypatch.setattr(graph_projection.projection, "reproject_assessment", fake_reproject)

    class _Sess:
        async def __aenter__(self): return object()
        async def __aexit__(self, *a): return False
    monkeypatch.setattr(graph_projection, "AsyncSessionLocal", lambda: _Sess())

    result = asyncio.run(graph_projection._run("abc-123"))
    assert result == {"nodes": 3, "edges": 2}
    assert calls["aid"] == "abc-123"
```

- [ ] **Step 4: Run test → fail → pass**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -m pytest tests/test_graph_projection_task.py -v`
Expected: PASS after the task module is in place. (No Neo4j needed — projection is mocked.)

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/adbygod_api/core/tasks/graph_projection.py apps/api/src/adbygod_api/core/celery_app.py apps/api/tests/test_graph_projection_task.py
git commit -m "feat(graph): Celery task to project assessment graph into Neo4j"
```

---

### Task 8: Projection state model + reproject endpoint

**Files:**
- Modify: `apps/api/src/adbygod_api/models.py` (add `GraphProjectionState`)
- Create: Alembic migration under `apps/api/alembic/versions/`
- Modify: `apps/api/src/adbygod_api/routes/graph.py` (add `POST /graph/{assessment_id}/reproject` + `GET /graph/{assessment_id}/projection-state`)
- Test: `apps/api/tests/test_graph_reproject_route.py`

- [ ] **Step 1: Add the state table**

In `apps/api/src/adbygod_api/models.py`, add (mirroring the existing model style):

```python
class GraphProjectionState(Base):
    __tablename__ = "graph_projection_state"

    assessment_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("assessments.id"), primary_key=True
    )
    last_projected_at: Mapped[datetime | None] = mapped_column(DateTime)
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|projecting|ready|error
```

- [ ] **Step 2: Generate the migration**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/alembic revision --autogenerate -m "add graph_projection_state"`
Then inspect the generated file under `alembic/versions/` and confirm it creates `graph_projection_state`. (SQLite dev creates tables via `create_all`; the migration is for Postgres.)

- [ ] **Step 3: Write the failing route test**

```python
# apps/api/tests/test_graph_reproject_route.py
from __future__ import annotations
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import uuid


def test_reproject_enqueues_and_reports_state(test_app, monkeypatch):
    from adbygod_api.routes import graph as graph_routes

    enq = {}
    monkeypatch.setattr(graph_routes, "_enqueue_projection",
                        lambda aid: enq.setdefault("aid", str(aid)))

    db = test_app["db"]
    admin = db.run(db.create_user("admin", "a@x.io", is_superadmin=True))
    ws = db.run(db.create_workspace("ws"))
    a = db.run(db.create_assessment("A", "d", workspace_id=ws.id, created_by=admin.id))
    headers = test_app["headers_for"](admin)

    r = test_app["client"].post(f"/api/graph/{a.id}/reproject", headers=headers)
    assert r.status_code in (200, 202)
    assert enq["aid"] == str(a.id)

    s = test_app["client"].get(f"/api/graph/{a.id}/projection-state", headers=headers)
    assert s.status_code == 200
    assert s.json()["status"] in ("pending", "projecting", "ready")
```

- [ ] **Step 4: Implement the endpoints**

In `apps/api/src/adbygod_api/routes/graph.py`, add a helper and two routes (reuse `require_assessment_write_access` / `require_assessment_access` like neighbouring routes):

```python
from adbygod_api.models import GraphProjectionState  # add to existing model imports


def _enqueue_projection(assessment_id) -> None:
    from adbygod_api.core.tasks.graph_projection import project_assessment
    project_assessment.delay(str(assessment_id))


@router.post("/{assessment_id}/reproject", status_code=202)
async def reproject_graph(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_write_access(db, user, assessment_id)
    state = await db.get(GraphProjectionState, assessment_id)
    if state is None:
        state = GraphProjectionState(assessment_id=assessment_id)
        db.add(state)
    state.status = "projecting"
    await db.commit()
    _enqueue_projection(assessment_id)
    return {"status": "projecting", "assessment_id": str(assessment_id)}


@router.get("/{assessment_id}/projection-state")
async def get_projection_state(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(db, user, assessment_id)
    state = await db.get(GraphProjectionState, assessment_id)
    if state is None:
        return {"assessment_id": str(assessment_id), "status": "pending",
                "node_count": 0, "edge_count": 0, "last_projected_at": None}
    return {
        "assessment_id": str(assessment_id), "status": state.status,
        "node_count": state.node_count, "edge_count": state.edge_count,
        "last_projected_at": state.last_projected_at.isoformat()
        if state.last_projected_at else None,
    }
```

Have the Celery task (`_run` in Task 7) update this row to `ready` with counts/`last_projected_at` on success and `error` on failure — add that write inside `_run` after `reproject_assessment` returns.

- [ ] **Step 5: Run test → fail → pass**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -m pytest tests/test_graph_reproject_route.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/api/src/adbygod_api/models.py apps/api/alembic/versions/ apps/api/src/adbygod_api/routes/graph.py apps/api/src/adbygod_api/core/tasks/graph_projection.py apps/api/tests/test_graph_reproject_route.py
git commit -m "feat(graph): projection-state table, reproject + state endpoints"
```

---

### Task 9: Enqueue projection from the ingest pipeline

**Files:**
- Modify: `apps/api/src/adbygod_api/routes/ingest.py:1399-1400`
- Test: `apps/api/tests/test_ingest_enqueues_projection.py`

- [ ] **Step 1: Write the failing test**

```python
# apps/api/tests/test_ingest_enqueues_projection.py
from __future__ import annotations
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adbygod_api.routes import ingest as ingest_routes


def test_ingest_calls_enqueue_projection(monkeypatch):
    # The post-commit hook must call the projection enqueue helper.
    assert hasattr(ingest_routes, "_enqueue_projection_after_ingest")
    called = {}
    monkeypatch.setattr(ingest_routes, "_enqueue_projection_after_ingest",
                        lambda aid: called.setdefault("aid", str(aid)))
    ingest_routes._enqueue_projection_after_ingest("xyz")
    assert called["aid"] == "xyz"
```

- [ ] **Step 2: Replace the cache-invalidation hook with projection enqueue**

At `apps/api/src/adbygod_api/routes/ingest.py:1398-1400`, replace:

```python
            # Invalidate graph cache so next graph request reflects new data
            from adbygod_api.routes.graph import invalidate_graph_cache
            invalidate_graph_cache(str(assessment_id))
```

with:

```python
            # Re-project the assessment graph into Neo4j (source of truth = Postgres)
            _enqueue_projection_after_ingest(str(assessment_id))
```

Add, near the top of `ingest.py` (module-level helper):

```python
def _enqueue_projection_after_ingest(assessment_id: str) -> None:
    from adbygod_api.core.tasks.graph_projection import project_assessment
    project_assessment.delay(str(assessment_id))
```

Apply the same replacement at the second call site (`core/ai_operator/tools/write_tools.py:228-229`).

- [ ] **Step 3: Run test → fail → pass**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -m pytest tests/test_ingest_enqueues_projection.py -v`
Expected: PASS.

- [ ] **Step 4: Confirm no remaining references to the removed cache invalidator**

Run: `grep -rn "invalidate_graph_cache" apps/api/src`
Expected: only the (soon-to-be-removed) definition in `graph.py`; no live callers. (The definition is deleted in Task 13.)

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/adbygod_api/routes/ingest.py apps/api/src/adbygod_api/core/ai_operator/tools/write_tools.py apps/api/tests/test_ingest_enqueues_projection.py
git commit -m "feat(graph): enqueue Neo4j projection after ingest"
```

---

# Phase 2 — Core traversal (merge gate)

### Task 10: Golden-fixture generator (freeze NetworkX outputs)

**Files:**
- Create: `apps/api/scripts/generate_graph_golden.py`
- Create: `apps/api/tests/fixtures/graph_golden/` (output dir, committed)

This runs the **existing** `ADGraphAnalyzer` once over a deterministic fixture graph and writes its outputs to JSON. The Neo4j implementation is later asserted against these frozen files. The NetworkX code is not imported by the runtime after Phase 6.

- [ ] **Step 1: Write the generator**

```python
# apps/api/scripts/generate_graph_golden.py
"""One-shot: freeze ADGraphAnalyzer outputs as golden fixtures.

Run:  cd apps/api && PYTHONPATH=src .venv/bin/python scripts/generate_graph_golden.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))
OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "graph_golden"
OUT.mkdir(parents=True, exist_ok=True)

from adbygod_api.core.graph.graph_service import ADGraphAnalyzer

# Deterministic sample: alice -MEMBER_OF-> helpdesk -GENERIC_ALL-> DA (tier0)
ENTITIES = [
    {"id": "n-alice", "entity_type": "USER", "sam_account_name": "alice", "tier": None},
    {"id": "n-helpdesk", "entity_type": "GROUP", "sam_account_name": "helpdesk", "tier": None},
    {"id": "n-da", "entity_type": "GROUP", "sam_account_name": "Domain Admins",
     "tier": 0, "is_crown_jewel": True},
]
EDGES = [
    {"id": "e1", "source_id": "n-alice", "target_id": "n-helpdesk", "edge_type": "MEMBER_OF"},
    {"id": "e2", "source_id": "n-helpdesk", "target_id": "n-da", "edge_type": "GENERIC_ALL"},
]


def _dump(name, obj):
    (OUT / f"{name}.json").write_text(json.dumps(obj, indent=2, sort_keys=True, default=str))


def main() -> None:
    g = ADGraphAnalyzer()
    g.load_from_dicts(ENTITIES, EDGES)

    sp = g.find_shortest_path("n-alice", "n-da")
    _dump("shortest_path_alice_da", _attack_path_to_dict(sp))

    allp = g.find_all_shortest_paths("n-alice", "n-da")
    _dump("all_shortest_paths_alice_da", [_attack_path_to_dict(p) for p in allp])

    _dump("export_for_frontend", g.export_for_frontend())
    print(f"wrote golden fixtures to {OUT}")


def _attack_path_to_dict(p):
    if p is None:
        return None
    import dataclasses
    return dataclasses.asdict(p)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Generate and commit the fixtures**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python scripts/generate_graph_golden.py`
Expected: `wrote golden fixtures to .../tests/fixtures/graph_golden`. Inspect the three JSON files; confirm `shortest_path_alice_da.json` has `node_ids: ["n-alice","n-helpdesk","n-da"]`.

- [ ] **Step 3: Commit**

```bash
git add apps/api/scripts/generate_graph_golden.py apps/api/tests/fixtures/graph_golden/
git commit -m "test(graph): freeze NetworkX golden fixtures for Neo4j parity"
```

---

### Task 11: `Neo4jGraphService` skeleton + lookups + node fetch

**Files:**
- Create: `apps/api/src/adbygod_api/core/graph/neo4j_graph_service.py`
- Create: `apps/api/src/adbygod_api/core/graph/cypher_mappers.py`
- Test: `apps/api/tests/test_neo4j_graph_service_paths.py` (lookups portion)

- [ ] **Step 1: Write the mapper helpers**

```python
# apps/api/src/adbygod_api/core/graph/cypher_mappers.py
"""Pure helpers turning Cypher path rows into the existing AttackPath dataclasses."""
from __future__ import annotations

from typing import Any

from adbygod_api.core.graph.graph_service import (  # dataclasses only, no runtime nx use
    AttackPath, PathStep, EDGE_RISK,
)

CONTROL_EDGES = {"GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "OWNS",
                 "FORCE_CHANGE_PASSWORD", "DCSYNC", "ADMIN_TO", "LOCAL_ADMIN"}


def _risk_level(score: float) -> str:
    if score >= 85: return "CRITICAL"
    if score >= 65: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


def build_attack_path(nodes: list[dict[str, Any]], rels: list[dict[str, Any]]) -> AttackPath:
    """nodes: ordered node props; rels: ordered relationship props (len = len(nodes)-1)."""
    steps: list[PathStep] = []
    edge_types: list[str] = []
    risk_sum = 0.0
    for i, n in enumerate(nodes):
        etype = rels[i - 1]["type"] if i > 0 else None
        erisk = float(rels[i - 1].get("risk_weight", EDGE_RISK.get(etype, 0.5))) if i > 0 else 0.0
        if etype:
            edge_types.append(etype)
            risk_sum += erisk
        steps.append(PathStep(
            node_id=n["id"], node_label=n.get("sam_account_name") or n.get("display_name") or n["id"],
            node_type=n.get("entity_type", "UNKNOWN"), tier=n.get("tier"),
            is_crown_jewel=bool(n.get("is_crown_jewel")), edge_type=etype, edge_risk=erisk,
        ))
    hop = len(nodes) - 1
    score = round((risk_sum / hop) * 100, 2) if hop else 0.0
    return AttackPath(
        source_id=nodes[0]["id"], target_id=nodes[-1]["id"],
        source_label=steps[0].node_label, target_label=steps[-1].node_label,
        hop_count=hop, path_score=score, risk_level=_risk_level(score),
        steps=steps, node_ids=[n["id"] for n in nodes], edge_types=edge_types,
        involves_credential_access=any(e in CONTROL_EDGES for e in edge_types),
    )
```

> **Parity caveat:** `path_score` math here is a starting approximation. Task 12 asserts against the golden fixture; iterate `build_attack_path` (and projected props) until the fixture matches. Read `ADGraphAnalyzer._build_attack_path` in `graph_service.py` for the exact scoring to replicate.

- [ ] **Step 2: Write the service skeleton + lookups**

```python
# apps/api/src/adbygod_api/core/graph/neo4j_graph_service.py
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
            rec = await (await s.run(
                "MATCH (n:Entity {id:$id, assessment_id:$aid}) RETURN n",
                id=node_id, aid=self.aid,
            )).single()
            return dict(rec["n"]) if rec else None

    async def _lookup(self, prop: str, value: str) -> Optional[str]:
        async with self._session() as s:
            rec = await (await s.run(
                f"MATCH (n:Entity {{assessment_id:$aid}}) WHERE n.{prop} = $v "
                "RETURN n.id AS id LIMIT 1", aid=self.aid, v=value,
            )).single()
            return rec["id"] if rec else None

    async def lookup_by_sam(self, sam: str) -> Optional[str]:
        return await self._lookup("sam_account_name", sam)

    async def lookup_by_dn(self, dn: str) -> Optional[str]:
        return await self._lookup("distinguished_name", dn)

    async def lookup_by_sid(self, sid: str) -> Optional[str]:
        return await self._lookup("object_sid", sid)
```

- [ ] **Step 3: Write the failing lookup test**

```python
# apps/api/tests/test_neo4j_graph_service_paths.py
from __future__ import annotations
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import pytest
from adbygod_api.config import settings
from adbygod_api.core.graph.neo4j_graph_service import Neo4jGraphService

AID = "11111111-1111-1111-1111-111111111111"


async def _seed(driver):
    async with driver.session(database=settings.NEO4J_DATABASE) as s:
        await s.run("MATCH (n {assessment_id:$aid}) DETACH DELETE n", aid=AID)
        await s.run(
            "CREATE (a:Entity {id:'n-alice', assessment_id:$aid, entity_type:'USER', "
            "sam_account_name:'alice'}) "
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
async def test_lookup_by_sam(neo4j_driver):
    await _seed(neo4j_driver)
    svc = Neo4jGraphService(AID)
    assert await svc.lookup_by_sam("alice") == "n-alice"
    node = await svc.get_node("n-da")
    assert node["entity_type"] == "GROUP"
    assert node["tier"] == 0
```

- [ ] **Step 4: Run → fail → pass**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -m pytest tests/test_neo4j_graph_service_paths.py::test_lookup_by_sam -v`
Expected: PASS (or SKIP without Docker).

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/adbygod_api/core/graph/neo4j_graph_service.py apps/api/src/adbygod_api/core/graph/cypher_mappers.py apps/api/tests/test_neo4j_graph_service_paths.py
git commit -m "feat(graph): Neo4jGraphService skeleton with lookups + node fetch"
```

---

### Task 12: Shortest / all-shortest / k-shortest paths (Cypher + GDS)

**Files:**
- Modify: `apps/api/src/adbygod_api/core/graph/neo4j_graph_service.py`
- Test: `apps/api/tests/test_neo4j_graph_service_paths.py` (add path tests asserting against golden fixtures)

- [ ] **Step 1: Add the path methods**

```python
    async def _path_to_attack(self, nodes, rels):
        from adbygod_api.core.graph.cypher_mappers import build_attack_path
        node_dicts = [dict(n) for n in nodes]
        rel_dicts = [{"type": r.type, **dict(r)} for r in rels]
        return build_attack_path(node_dicts, rel_dicts)

    async def find_shortest_path(self, source_id, target_id, max_hops: int = 12):
        cypher = (
            "MATCH (s:Entity {id:$s, assessment_id:$aid}), "
            "(t:Entity {id:$t, assessment_id:$aid}) "
            "MATCH p = shortestPath((s)-[*..%d]->(t)) "
            "RETURN nodes(p) AS ns, relationships(p) AS rs" % max_hops
        )
        async with self._session() as ses:
            rec = await (await ses.run(cypher, s=source_id, t=target_id, aid=self.aid)).single()
            if not rec:
                return None
            return await self._path_to_attack(rec["ns"], rec["rs"])

    async def find_all_shortest_paths(self, source_id, target_id, max_hops: int = 12, limit: int = 10):
        cypher = (
            "MATCH (s:Entity {id:$s, assessment_id:$aid}), "
            "(t:Entity {id:$t, assessment_id:$aid}) "
            "MATCH p = allShortestPaths((s)-[*..%d]->(t)) "
            "RETURN nodes(p) AS ns, relationships(p) AS rs LIMIT $lim" % max_hops
        )
        out = []
        async with self._session() as ses:
            result = await ses.run(cypher, s=source_id, t=target_id, aid=self.aid, lim=limit)
            async for rec in result:
                out.append(await self._path_to_attack(rec["ns"], rec["rs"]))
        return out
```

For `find_k_shortest_paths`, use GDS Yen's over an ephemeral projection scoped to the assessment (create a named projection of nodes/rels with `assessment_id = $aid`, run `gds.shortestPath.yens.stream`, drop the projection). Provide the implementation and iterate against a k-shortest golden fixture (add `find_k_shortest_paths` output to `generate_graph_golden.py` in Task 10 if not already present, regenerate, and assert).

- [ ] **Step 2: Add parity tests against the golden fixtures**

```python
import json

GOLDEN = Path(__file__).resolve().parents[0] / "fixtures" / "graph_golden"


def _norm(ap_dict):
    # Compare only the stable, semantically-meaningful fields.
    return {
        "node_ids": ap_dict["node_ids"],
        "edge_types": ap_dict["edge_types"],
        "hop_count": ap_dict["hop_count"],
        "source_id": ap_dict["source_id"],
        "target_id": ap_dict["target_id"],
    }


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_shortest_path_matches_golden(neo4j_driver):
    import dataclasses
    await _seed(neo4j_driver)
    svc = Neo4jGraphService(AID)
    got = await svc.find_shortest_path("n-alice", "n-da")
    golden = json.loads((GOLDEN / "shortest_path_alice_da.json").read_text())
    assert _norm(dataclasses.asdict(got)) == _norm(golden)
```

> The golden fixture uses node ids `n-alice`/`n-helpdesk`/`n-da`; `_seed` uses the same ids, so `node_ids` compare directly. If `path_score` parity is required, extend `_norm` to include it and tune `build_attack_path` until equal.

- [ ] **Step 3: Run → iterate → pass**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -m pytest tests/test_neo4j_graph_service_paths.py -v`
Expected: all path tests PASS (or SKIP without Docker). Iterate Cypher/mapper until green.

- [ ] **Step 4: Commit**

```bash
git add apps/api/src/adbygod_api/core/graph/neo4j_graph_service.py apps/api/tests/test_neo4j_graph_service_paths.py apps/api/tests/fixtures/graph_golden/
git commit -m "feat(graph): Cypher/GDS path queries with NetworkX parity"
```

---

### Task 13: Reachability + neighborhood + `export_for_frontend`

**Files:**
- Modify: `apps/api/src/adbygod_api/core/graph/neo4j_graph_service.py`
- Test: `apps/api/tests/test_neo4j_graph_export_parity.py`

- [ ] **Step 1: Add reachability, neighborhood, and export**

Add `get_reachable_from`, `get_can_reach`, `get_neighborhood(node_id, hops, max_nodes)`, and `export_for_frontend(...)`. `export_for_frontend` must return the **same dict shape** as the golden `export_for_frontend.json` (top-level `nodes`/`edges`/`stats` keys). Read the existing `ADGraphAnalyzer.export_for_frontend` (graph_service.py ~line 1924) for the exact keys per node/edge, and build the equivalent from a Cypher scan:

```python
    async def export_for_frontend(self, limit: int | None = None):
        async with self._session() as ses:
            nrows = await ses.run(
                "MATCH (n:Entity {assessment_id:$aid}) RETURN n", aid=self.aid)
            nodes = [self._node_view(dict(r["n"])) async for r in nrows]
            erows = await ses.run(
                "MATCH (s:Entity {assessment_id:$aid})-[r]->(t:Entity {assessment_id:$aid}) "
                "RETURN s.id AS s, t.id AS t, type(r) AS et, r.risk_weight AS rw, r.id AS id",
                aid=self.aid)
            edges = [{"id": r["id"], "source": r["s"], "target": r["t"],
                      "type": r["et"], "risk_weight": r["rw"]} async for r in erows]
        return {"nodes": nodes, "edges": edges}

    def _node_view(self, n: dict) -> dict:
        return {"id": n["id"], "type": n.get("entity_type", "UNKNOWN"),
                "label": n.get("sam_account_name") or n.get("display_name") or n["id"],
                "tier": n.get("tier"), "is_crown_jewel": bool(n.get("is_crown_jewel"))}
```

- [ ] **Step 2: Write the export parity test**

```python
# apps/api/tests/test_neo4j_graph_export_parity.py
from __future__ import annotations
import sys, json
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import pytest
from adbygod_api.config import settings
from adbygod_api.core.graph.neo4j_graph_service import Neo4jGraphService

GOLDEN = Path(__file__).resolve().parents[0] / "fixtures" / "graph_golden"
AID = "22222222-2222-2222-2222-222222222222"


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_export_node_and_edge_sets_match_golden(neo4j_driver):
    async with neo4j_driver.session(database=settings.NEO4J_DATABASE) as s:
        await s.run("MATCH (n {assessment_id:$aid}) DETACH DELETE n", aid=AID)
        await s.run(
            "CREATE (a:Entity {id:'n-alice', assessment_id:$aid, entity_type:'USER', sam_account_name:'alice'}) "
            "CREATE (h:Entity {id:'n-helpdesk', assessment_id:$aid, entity_type:'GROUP', sam_account_name:'helpdesk'}) "
            "CREATE (d:Entity {id:'n-da', assessment_id:$aid, entity_type:'GROUP', sam_account_name:'Domain Admins', tier:0, is_crown_jewel:true}) "
            "CREATE (a)-[:MEMBER_OF {id:'e1', risk_weight:0.5}]->(h) "
            "CREATE (h)-[:GENERIC_ALL {id:'e2', risk_weight:1.0}]->(d)", aid=AID)

    got = await Neo4jGraphService(AID).export_for_frontend()
    golden = json.loads((GOLDEN / "export_for_frontend.json").read_text())

    assert {n["id"] for n in got["nodes"]} == {n["id"] for n in golden["nodes"]}
    assert {(e["source"], e["target"], e["type"]) for e in got["edges"]} == \
           {(e["source"], e["target"], e["type"]) for e in golden["edges"]}
```

> If the golden export nests nodes/edges under different keys, adapt `_node_view`/`export_for_frontend` to match. The frontend contract is the golden file — make the Neo4j output equal it.

- [ ] **Step 3: Run → iterate → pass**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -m pytest tests/test_neo4j_graph_export_parity.py -v`
Expected: PASS (or SKIP without Docker).

- [ ] **Step 4: Commit**

```bash
git add apps/api/src/adbygod_api/core/graph/neo4j_graph_service.py apps/api/tests/test_neo4j_graph_export_parity.py
git commit -m "feat(graph): reachability, neighborhood, export_for_frontend on Neo4j"
```

---

### Task 14: Switch graph routes to `Neo4jGraphService`; remove `_graph_cache`

**Files:**
- Modify: `apps/api/src/adbygod_api/routes/graph.py`
- Test: `apps/api/tests/test_graph_route_neo4j.py`

- [ ] **Step 1: Replace `_get_analyzer` with `_get_service`**

In `apps/api/src/adbygod_api/routes/graph.py`:
- Delete `_graph_cache`, `_CACHE_TTL`, `_CACHE_MAX`, `_graph_cache_lock`, `invalidate_graph_cache`, and the `_get_analyzer` function (lines ~105–170).
- Remove the `from adbygod_api.core.graph.graph_service import ADGraphAnalyzer` import.
- Add:

```python
from adbygod_api.core.graph.neo4j_graph_service import Neo4jGraphService


def _get_service(assessment_id: str) -> Neo4jGraphService:
    return Neo4jGraphService(str(assessment_id))
```

- Replace every `analyzer = await _get_analyzer(str(assessment_id), db)` with `service = _get_service(str(assessment_id))`, and update call sites: the path methods are now `await`ed coroutines (e.g. `await service.find_k_shortest_paths(...)`). The existing `_run_path_with_timeout` wrapper (sync→thread) is replaced by `asyncio.wait_for(service.find_..., timeout=settings.GRAPH_QUERY_TIMEOUT_SECONDS)`; update `_run_path_with_timeout` accordingly or inline the `wait_for`.

> Only the methods implemented in Tasks 11–13 are wired now. Routes that call not-yet-ported analyzer methods (centrality, detectors, simulation — spec Phases 3–5) must be temporarily guarded: return `501 Not Implemented` with a clear message, behind a `# TODO(phase-3..5)` marker, so the app imports and the merge-gate routes work. List these guarded routes in the PR description.

Also handle Neo4j-unavailable (spec §9): wrap the service calls in the graph routes so a `neo4j.exceptions.ServiceUnavailable` or the `RuntimeError("Neo4j driver not initialised")` from `get_driver()` is translated to `HTTPException(status_code=503, detail="graph engine unavailable")`. Add a small dependency/helper, e.g.:

```python
from neo4j.exceptions import ServiceUnavailable

async def _safe(coro):
    try:
        return await coro
    except (ServiceUnavailable, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="graph engine unavailable") from exc
```

and call route service methods via `await _safe(service.find_shortest_path(...))`.

- [ ] **Step 2: Write the route test (Neo4j-backed shortest path through HTTP)**

```python
# apps/api/tests/test_graph_route_neo4j.py
from __future__ import annotations
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import pytest
from adbygod_api.config import settings


@pytest.mark.neo4j
def test_attack_path_route_returns_neo4j_result(test_app, neo4j_driver):
    import asyncio
    db = test_app["db"]
    admin = db.run(db.create_user("admin", "a@x.io", is_superadmin=True))
    ws = db.run(db.create_workspace("ws"))
    a = db.run(db.create_assessment("A", "d", workspace_id=ws.id, created_by=admin.id))
    headers = test_app["headers_for"](admin)
    aid = str(a.id)

    async def _seed():
        async with neo4j_driver.session(database=settings.NEO4J_DATABASE) as s:
            await s.run(
                "CREATE (x:Entity {id:'s', assessment_id:$aid, entity_type:'USER', sam_account_name:'src'}) "
                "CREATE (y:Entity {id:'d', assessment_id:$aid, entity_type:'GROUP', sam_account_name:'Domain Admins', tier:0}) "
                "CREATE (x)-[:GENERIC_ALL {id:'e', risk_weight:1.0}]->(y)", aid=aid)
    asyncio.run(_seed())

    # Use the actual path endpoint shape from routes/graph.py (adjust path/params to match).
    r = test_app["client"].get(
        f"/api/graph/{aid}/paths", params={"source": "s", "target": "d"}, headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert any("d" in (p.get("node_ids") or p.get("path") or []) for p in body.get("paths", [body]))
```

> Adjust the endpoint path/params/response-key assertions to the real route in `graph.py` (the exact path-query route). Keep the assertion: the response is sourced from the Neo4j seed.

- [ ] **Step 3: Run → iterate → pass; then run the whole graph test group**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -m pytest tests/test_graph_route_neo4j.py tests/test_neo4j_graph_service_paths.py tests/test_neo4j_graph_export_parity.py -v`
Expected: PASS (or SKIP without Docker).

- [ ] **Step 4: Full suite regression (non-Neo4j tests must be unaffected)**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -m pytest -q -m "not neo4j"`
Expected: the existing suite passes as before (no import errors from the graph-route changes). Fix any breakage from removed symbols (`invalidate_graph_cache`, `ADGraphAnalyzer` import) before continuing.

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/adbygod_api/routes/graph.py apps/api/tests/test_graph_route_neo4j.py
git commit -m "feat(graph): serve graph routes from Neo4j; remove in-memory cache"
```

---

### Task 15: Phase 0–2 verification gate

**Files:** none (verification only)

- [ ] **Step 1: Type-check and lint the API**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -c "import adbygod_api.main"` and the repo's configured linters (`ruff`/`flake8` if present under `apps/api`).
Expected: clean import; lint clean.

- [ ] **Step 2: Full graph test group with Neo4j**

Run: `cd apps/api && PYTHONPATH=src .venv/bin/python -m pytest -m neo4j -v`
Expected: all `neo4j`-marked tests PASS against the testcontainer.

- [ ] **Step 3: End-to-end smoke (manual, documented)**

Bring up dev Neo4j: `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d neo4j redis`.
Start the API, import a small BloodHound sample, trigger `POST /api/graph/{id}/reproject`, poll `GET /api/graph/{id}/projection-state` until `ready`, then load the Graph Explorer + Attack Paths views and confirm nodes/edges/paths render. Record the result in the PR description.

- [ ] **Step 4: Confirm merge-gate scope**

Verify: graph traversal/export routes work on Neo4j; analytics/detector/simulation routes return `501` with the `phase-3..5` marker; no runtime import of NetworkX from request paths except `cypher_mappers` (dataclasses only).
Run: `grep -rn "import networkx\|from networkx\|graph_service import ADGraphAnalyzer" apps/api/src/adbygod_api/routes apps/api/src/adbygod_api/core/graph/neo4j_graph_service.py`
Expected: no `networkx` import on the request path; `cypher_mappers` imports only dataclasses/constants from `graph_service`.

- [ ] **Step 5: Open the PR**

```bash
git push -u origin feat/neo4j-graph-engine
gh pr create --title "Neo4j graph engine — foundation (Phases 0–2)" \
  --body "Projection + Cypher traversal behind the existing graph routes. Phases 3–6 follow. See docs/superpowers/specs/2026-06-10-neo4j-graph-engine-design.md"
```

---

## Deferred to follow-on plans (spec Phases 3–6)

- **Phase 3 — GDS analytics:** centrality, Louvain communities, blast radius, choke points, critical nodes, domain dominance (replaces `python-louvain` + NetworkX centrality). Un-501 the analytics routes.
- **Phase 4 — Detectors:** `detect_*` Cypher pattern queries (kerberoastable, AS-REP, ADCS ESC, shadow admins, DCSync, delegation, LAPS/gMSA). Requires extending projection to flatten the `attributes` keys each detector reads.
- **Phase 5 — Simulation:** `simulate_edge_removal`, `simulate_node_hardening`, `rank_remediation_actions` via GDS in-memory projections.
- **Phase 6 — Cleanup:** delete runtime `graph_service.py`, drop `networkx`/`python-louvain` deps, remove residual cache plumbing.

Each follow-on plan is written after the prior phase merges and its Cypher patterns are proven against a live Neo4j.
