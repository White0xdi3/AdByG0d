"""Celery task: (re)project an assessment's graph into Neo4j after ingest.

Runs under the default prefork pool: each task is a synchronous call in a
forked process, so ``asyncio.run`` (a fresh event loop per task) is correct.
Do NOT switch this worker to the gevent/eventlet cooperative pools without a
loop adapter — ``asyncio.run`` conflicts with their monkeypatched loop.
"""
from __future__ import annotations

import asyncio
import logging

from adbygod_api.core.celery_app import celery_app
from adbygod_api.core.graph import neo4j_client, projection
from adbygod_api.database import AsyncSessionLocal

log = logging.getLogger(__name__)


async def _run(assessment_id: str) -> dict[str, int]:
    # connect()+close() per task: asyncio.run creates a fresh event loop each
    # call and closes it on return. The Neo4j driver binds its internals to the
    # loop alive at creation, so a singleton reused across tasks would operate
    # on a closed loop and fail on the 2nd task in a long-lived worker. Closing
    # here forces the next connect() to build a fresh driver on the new loop.
    await neo4j_client.connect()
    try:
        async with AsyncSessionLocal() as db:
            return await projection.reproject_assessment(db, assessment_id)
    finally:
        await neo4j_client.close()


@celery_app.task(
    name="graph.project_assessment",
    queue="offensive_jobs",
    acks_late=True,
    reject_on_worker_lost=True,
)
def project_assessment(assessment_id: str) -> dict[str, int]:
    return asyncio.run(_run(assessment_id))
