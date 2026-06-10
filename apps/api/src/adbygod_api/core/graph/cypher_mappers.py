"""Pure helpers turning Cypher path rows into the existing AttackPath dataclasses.

The scoring/labelling/explanation logic here is a faithful port of
``ADGraphAnalyzer._build_attack_path`` in ``graph_service.py`` so that the
Neo4j-backed engine reproduces the validated NetworkX outputs exactly (asserted
against the frozen golden fixtures). Where a helper in ``graph_service`` is a
module-level pure function we import and reuse it rather than re-deriving it,
to avoid Python↔Python drift.
"""
from __future__ import annotations

from typing import Any

from adbygod_api.core.graph.graph_service import (  # dataclasses + pure helpers, no runtime nx use
    AttackPath,
    PathStep,
    EDGE_RISK,
    CREDENTIAL_EDGES,
    HVT_TYPES,
    HVT_SAM_PATTERNS,
    _safe_float,
    _explain_edge,
    _build_explanation,
)

# Edge-type sets that set the boolean flags on AttackPath. Kept verbatim from
# ADGraphAnalyzer._build_attack_path so the flags match the golden fixtures.
_DELEGATION_EDGES = {"ALLOWED_TO_DELEGATE", "ALLOWED_TO_ACT"}


def _risk_level(score: float) -> str:
    # Mirrors ADGraphAnalyzer._risk_level_from_score.
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _label_of(node: dict[str, Any]) -> str:
    # Mirrors ADGraphAnalyzer._label_of: sam → display → dns → truncated id.
    return (
        node.get("sam_account_name")
        or node.get("display_name")
        or node.get("dns_hostname")
        or node["id"][:16]
    )


def _is_tier0(node: dict[str, Any]) -> bool:
    """Per-node Tier-0 membership, mirroring ADGraphAnalyzer._build_tier0_index.

    The analyzer's ``_tier0`` set is derived purely from node attributes (no
    transitive group membership), so it can be reproduced from projected props:
    explicit tier 0, crown jewel, a high-value entity type, or a SAM name that
    contains a high-value pattern (e.g. "domain admins", "krbtgt").
    """
    if node.get("tier") == 0 or node.get("is_crown_jewel"):
        return True
    if node.get("entity_type", "") in HVT_TYPES:
        return True
    sam = (node.get("sam_account_name") or "").lower()
    return any(pattern in sam for pattern in HVT_SAM_PATTERNS)


def _effective_tier(node: dict[str, Any]) -> Any:
    """Tier reported on a PathStep, mirroring the analyzer's back-propagation.

    ``_build_tier0_index`` sets ``tier = 0`` in entity_meta for Tier-0 nodes
    whose original tier was ``None`` (leaving any explicit tier untouched). The
    projected node carries the raw Postgres tier, so we apply the same rule here.
    """
    tier = node.get("tier")
    if tier is None and _is_tier0(node):
        return 0
    return tier


def build_attack_path(nodes: list[dict[str, Any]], rels: list[dict[str, Any]]) -> AttackPath:
    """Build an AttackPath from an ordered Cypher path.

    nodes: ordered node-property dicts (len = n).
    rels:  ordered relationship-property dicts (len = n - 1); each MUST carry a
           ``type`` key (the relationship type) and may carry ``risk_weight``,
           ``provenance`` and ``edge_confidence`` (as emitted by projection).

    The math is a faithful port of ADGraphAnalyzer._build_attack_path. The one
    intentional simplification: when parallel relationships exist between the
    same pair of entities the analyzer scores using the highest-risk parallel
    edge, whereas here we use whichever relationship the Cypher path traversed.
    For single-edge graphs (all current fixtures and the common case) these
    coincide; richer multi-edge parity is a follow-on concern.
    """
    if len(nodes) < 2:
        return AttackPath(
            source_id=nodes[0]["id"] if nodes else "",
            target_id=nodes[-1]["id"] if nodes else "",
            source_label=_label_of(nodes[0]) if nodes else "",
            target_label=_label_of(nodes[-1]) if nodes else "",
            hop_count=0, path_score=0.0, risk_level="LOW",
            node_ids=[n["id"] for n in nodes], edge_types=[],
        )

    # Callers must supply exactly one relationship per hop; fail loud on misuse
    # rather than IndexError deep in the loop below.
    if len(rels) != len(nodes) - 1:
        raise ValueError(
            f"build_attack_path: expected {len(nodes) - 1} rels, got {len(rels)}"
        )

    steps: list[PathStep] = []
    edge_types: list[str] = []
    involves_cred = involves_deleg = involves_adcs = crosses_trust = False

    for i, n in enumerate(nodes):
        label = _label_of(n)
        step = PathStep(
            node_id=n["id"], node_label=label,
            node_type=n.get("entity_type", "UNKNOWN"),
            tier=_effective_tier(n), is_crown_jewel=bool(n.get("is_crown_jewel")),
        )
        if i < len(nodes) - 1:
            r = rels[i]
            etype = r.get("type", "UNKNOWN")
            rw = _safe_float(r.get("risk_weight"), EDGE_RISK.get(etype, 0.5))
            step.edge_type = etype
            step.edge_risk = rw
            step.edge_provenance = r.get("provenance")
            step.explanation = _explain_edge(etype, label, _label_of(nodes[i + 1]))
            edge_types.append(etype)
            if etype in CREDENTIAL_EDGES:
                involves_cred = True
            if etype in _DELEGATION_EDGES:
                involves_deleg = True
            if etype == "CAN_ENROLL":
                involves_adcs = True
            if etype == "TRUSTS":
                crosses_trust = True
        steps.append(step)

    # Per-hop risk weights and edge confidences (the projection always emits
    # both; _safe_float/defaults keep parity if a test seed omits them).
    step_risks = [_safe_float(r.get("risk_weight"), 0.5) for r in rels]
    edge_confidences = [float(r.get("edge_confidence", 1.0)) for r in rels]
    avg_risk = sum(step_risks) / max(len(step_risks), 1)
    confidence = min(edge_confidences) if edge_confidences else 1.0

    hop_count = len(nodes) - 1
    tier0_proximity = 1.0 if any(_is_tier0(n) for n in nodes[1:]) else 0.5
    raw_score = (
        avg_risk * 0.40
        + (1.0 / max(hop_count, 1)) * 0.20
        + tier0_proximity * 0.20
        + (0.10 if involves_cred else 0.0)
        + (0.10 if involves_deleg else 0.0)
    )
    path_score = round(min(raw_score, 1.0) * 100, 2)

    # Cap score by edge confidence (matches the analyzer's confidence gate).
    if confidence < 0.5:
        path_score = min(path_score, 70.0)
    elif confidence < 0.8:
        path_score = min(path_score, 85.0)

    return AttackPath(
        source_id=nodes[0]["id"], target_id=nodes[-1]["id"],
        source_label=steps[0].node_label, target_label=steps[-1].node_label,
        hop_count=hop_count, path_score=path_score,
        risk_level=_risk_level(path_score),
        steps=steps, node_ids=[n["id"] for n in nodes], edge_types=edge_types,
        involves_credential_access=involves_cred, involves_delegation=involves_deleg,
        involves_adcs=involves_adcs, crosses_trust=crosses_trust,
        explanation=_build_explanation(steps), confidence=confidence,
    )
