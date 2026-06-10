"""Pure helpers turning Cypher path rows into the existing AttackPath dataclasses."""
from __future__ import annotations

from typing import Any

from adbygod_api.core.graph.graph_service import AttackPath, PathStep, EDGE_RISK

CONTROL_EDGES = {"GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "OWNS",
                 "FORCE_CHANGE_PASSWORD", "DCSYNC", "ADMIN_TO", "LOCAL_ADMIN"}


def _risk_level(score: float) -> str:
    if score >= 85: return "CRITICAL"
    if score >= 65: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


def build_attack_path(nodes: list[dict[str, Any]], rels: list[dict[str, Any]]) -> AttackPath:
    """nodes: ordered node prop dicts; rels: ordered rel prop dicts (len = len(nodes)-1).
    Each rel dict must include a 'type' key (the relationship type) and may include 'risk_weight'.
    """
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
            node_id=n["id"],
            node_label=n.get("sam_account_name") or n.get("display_name") or n["id"],
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
