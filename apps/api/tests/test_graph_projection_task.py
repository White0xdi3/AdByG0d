from __future__ import annotations

import asyncio

from adbygod_api.core.tasks import graph_projection


def test_task_invokes_projection(monkeypatch):
    calls = {"closed": 0}

    async def fake_connect():
        return None

    async def fake_close():
        calls["closed"] += 1

    async def fake_reproject(db, aid):
        calls["aid"] = aid
        return {"nodes": 3, "edges": 2}

    monkeypatch.setattr(graph_projection.neo4j_client, "connect", fake_connect)
    monkeypatch.setattr(graph_projection.neo4j_client, "close", fake_close)
    monkeypatch.setattr(graph_projection.projection, "reproject_assessment", fake_reproject)

    class _Sess:
        async def __aenter__(self):
            return object()
        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(graph_projection, "AsyncSessionLocal", lambda: _Sess())

    result = asyncio.run(graph_projection._run("abc-123"))
    assert result == {"nodes": 3, "edges": 2}
    assert calls["aid"] == "abc-123"
    # The driver must be closed per task so the next task's connect() rebuilds
    # it on a fresh event loop (asyncio.run closes the current loop on return).
    assert calls["closed"] == 1


def test_task_closes_driver_even_on_error(monkeypatch):
    closed = {"n": 0}

    async def fake_connect():
        return None

    async def fake_close():
        closed["n"] += 1

    async def boom(db, aid):
        raise RuntimeError("projection failed")

    monkeypatch.setattr(graph_projection.neo4j_client, "connect", fake_connect)
    monkeypatch.setattr(graph_projection.neo4j_client, "close", fake_close)
    monkeypatch.setattr(graph_projection.projection, "reproject_assessment", boom)

    class _Sess:
        async def __aenter__(self):
            return object()
        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(graph_projection, "AsyncSessionLocal", lambda: _Sess())

    import pytest

    with pytest.raises(RuntimeError, match="projection failed"):
        asyncio.run(graph_projection._run("abc-123"))
    assert closed["n"] == 1  # finally-block close still runs on failure
