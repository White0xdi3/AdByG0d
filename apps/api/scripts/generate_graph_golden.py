"""One-shot: freeze ADGraphAnalyzer outputs as golden fixtures.

Run: cd apps/api && PYTHONPATH=src .venv/bin/python scripts/generate_graph_golden.py

The NetworkX reference implementation is used ONLY to generate these fixtures;
the Neo4j engine is later asserted against the frozen files.
"""
from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "graph_golden"
OUT.mkdir(parents=True, exist_ok=True)

from adbygod_api.core.graph.graph_service import ADGraphAnalyzer  # noqa: E402

# ---------------------------------------------------------------------------
# Deterministic sample graph
#   alice  --MEMBER_OF-->  helpdesk  --GENERIC_ALL-->  Domain Admins (tier=0)
# ---------------------------------------------------------------------------
ENTITIES = [
    {
        "id": "n-alice",
        "entity_type": "USER",
        "sam_account_name": "alice",
        "tier": None,
        "is_crown_jewel": False,
        "attributes": {},
    },
    {
        "id": "n-helpdesk",
        "entity_type": "GROUP",
        "sam_account_name": "helpdesk",
        "tier": None,
        "is_crown_jewel": False,
        "attributes": {},
    },
    {
        "id": "n-da",
        "entity_type": "GROUP",
        "sam_account_name": "Domain Admins",
        "tier": 0,
        "is_crown_jewel": True,
        "attributes": {},
    },
]

EDGES = [
    {
        "id": "e1",
        "source_id": "n-alice",
        "target_id": "n-helpdesk",
        "edge_type": "MEMBER_OF",
        "risk_weight": 0.5,
    },
    {
        "id": "e2",
        "source_id": "n-helpdesk",
        "target_id": "n-da",
        "edge_type": "GENERIC_ALL",
        "risk_weight": 1.0,
    },
]


def _dump(name: str, obj: object) -> None:
    path = OUT / f"{name}.json"
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, default=str))
    print(f"  wrote {path}")


def _ap(p):
    """Convert AttackPath (or None) to a JSON-serialisable dict."""
    return dataclasses.asdict(p) if p is not None else None


def main() -> None:
    g = ADGraphAnalyzer()
    g.load_from_dicts(ENTITIES, EDGES)

    _dump(
        "shortest_path_alice_da",
        _ap(g.find_shortest_path("n-alice", "n-da")),
    )
    _dump(
        "all_shortest_paths_alice_da",
        [_ap(p) for p in g.find_all_shortest_paths("n-alice", "n-da")],
    )
    _dump(
        "k_shortest_paths_alice_da",
        [_ap(p) for p in g.find_k_shortest_paths("n-alice", "n-da", k=5)],
    )
    _dump(
        "export_for_frontend",
        g.export_for_frontend(),
    )

    print(f"\nGolden fixtures written to: {OUT}")


if __name__ == "__main__":
    main()
