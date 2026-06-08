from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import math
import re
from typing import Any, Iterable
from uuid import UUID

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.core.analyzers.scoring_service import RiskScoringService
from adbygod_api.core.graph.graph_service import ADGraphAnalyzer
from adbygod_api.core.security.authorization import require_assessment_access
from adbygod_api.models import (
    Assessment,
    AttackChain,
    CertTemplate,
    DataOrigin,
    Entity,
    EntityType,
    EvidenceRecord,
    ExposurePath,
    Finding,
    FindingEvidence,
    FindingStatus,
    GraphEdge,
    PlatformUser,
    SeverityLevel,
    ValidationRun,
)

REPORT_SECTION_CATALOG: tuple[dict[str, str], ...] = (
    {"id": "exec_summary", "label": "Executive Summary", "description": "Board-ready assessment synopsis, risk score, and immediate priorities."},
    {"id": "scope_methodology", "label": "Scope and Methodology", "description": "Assessment metadata, timing, modules, and provenance rules."},
    {"id": "risk_posture", "label": "Risk Posture", "description": "Severity, module, provenance, and graph-backed scoring breakdown."},
    {"id": "coverage_assurance", "label": "Finding Coverage Assurance", "description": "Reconciles report content against every stored finding and flags completeness gaps."},
    {"id": "risk_themes", "label": "Risk Themes", "description": "Clusters findings into Active Directory threat themes for executive prioritization."},
    {"id": "priority_action_board", "label": "Priority Action Board", "description": "Immediate, near-term, and planned actions ranked from live findings."},
    {"id": "data_quality", "label": "Data Quality and Confidence", "description": "Evidence linkage, finding confidence, and report-readiness posture."},
    {"id": "finding_register", "label": "Finding Register", "description": "Complete ordered register of every identified finding."},
    {"id": "detailed_findings", "label": "Detailed Findings", "description": "Descriptions, impact drivers, affected objects, evidence references, and remediation."},
    {"id": "attack_paths", "label": "Attack Paths", "description": "Persisted exposure paths with scores, tiers, and path explanations."},
    {"id": "graph_posture", "label": "Graph Posture", "description": "Identity graph inventory and relationship concentration."},
    {"id": "identity_inventory", "label": "Identity Inventory", "description": "Entity, Tier-0, privileged, and crown-jewel inventory rollups."},
    {"id": "pki_posture", "label": "PKI Posture", "description": "AD CS template posture and ESC exposure summary."},
    {"id": "trust_posture", "label": "Trust Posture", "description": "Trust relationships, SID filtering, and selective authentication posture."},
    {"id": "service_accounts", "label": "Service Account Posture", "description": "Service-account roastability, delegation, and staleness signals."},
    {"id": "validation", "label": "Validation History", "description": "Validation-run outcomes labeled as simulated or evidence-backed."},
    {"id": "remediation_plan", "label": "Remediation Workplan", "description": "Prioritized fix order derived from score, status, and remediation metadata."},
    {"id": "evidence_appendix", "label": "Evidence Appendix", "description": "Provenance-safe evidence index with sensitive-value redaction."},
    {"id": "execution_summary", "label": "Execution Summary", "description": "Assessment-scoped chain/loot counts without exposing operational secrets."},
    {"id": "raw_context", "label": "Raw Context", "description": "Sanitized assessment statistics and report-generation context."},
)

_SECTION_IDS = tuple(section["id"] for section in REPORT_SECTION_CATALOG)
_SECTION_ID_SET = set(_SECTION_IDS)
SECTION_ALIASES: dict[str, str] = {
    # Preserve compatibility with the older Reports UI section tokens.
    "severity_breakdown": "risk_posture",
    "module_breakdown": "risk_posture",
    "top_findings": "finding_register",
    "timeline": "scope_methodology",
}
DEFAULT_REPORT_SECTIONS: tuple[str, ...] = (
    "exec_summary",
    "scope_methodology",
    "risk_posture",
    "coverage_assurance",
    "risk_themes",
    "priority_action_board",
    "data_quality",
    "finding_register",
    "detailed_findings",
    "attack_paths",
    "graph_posture",
    "identity_inventory",
    "pki_posture",
    "trust_posture",
    "service_accounts",
    "validation",
    "remediation_plan",
    "evidence_appendix",
    "execution_summary",
)

REPORT_MODULE_SOURCE_ID_ALIASES: dict[str, set[str]] = {
    # Finding.module stores report-facing categories, while Assessment.modules_run
    # stores collector module IDs. Keep this intentionally conservative: it only
    # prevents clearly matched modules from being called "without findings".
    "kerberos": {"kerberos", "kerberos_policy_enum"},
    "password_policy": {"passwords", "domain_policy_deep", "password_spray_surface"},
    "user_accounts": {"enum", "account_lifecycle", "passwords"},
    "network_posture": {"network_posture", "smb", "legacy_protocols", "firewall_enum", "wmi_exposure"},
    "local_admin": {"laps", "laps_coverage", "local_admin_spread"},
    "acl_abuse": {"acl", "acl_deep", "security_desc", "tiering_crown_jewels"},
}


def _module_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _source_module_ids_for_finding_module(module: Any) -> set[str]:
    key = _module_key(module)
    return set(REPORT_MODULE_SOURCE_ID_ALIASES.get(key, {key}))


_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_STATUS_REMEDIATION_PRIORITY = {
    FindingStatus.REGRESSED.value: 0,
    FindingStatus.OPEN.value: 1,
    FindingStatus.IN_REVIEW.value: 2,
    FindingStatus.ACCEPTED.value: 3,
    FindingStatus.FALSE_POSITIVE.value: 4,
    FindingStatus.REMEDIATED.value: 5,
}
_SAFE_FILENAME_RE = re.compile(r"[^a-zA-Z0-9._-]+")

_SENSITIVE_KEY_TOKENS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "authorization",
    "credential",
    "cleartext",
    "private_key",
    "session_key",
    "nt_hash",
    "lm_hash",
    "hash",
    "ticket",
    "kirbi",
    "ccache",
    "api_key",
    "cookie",
)
_SAFE_KEY_EXCEPTIONS = {
    "hash_type",
    "hashcat_mode",
    "john_format",
    "evidence_hash",
    "policy_hash",
    "certificate_hash_algorithm",
}


def enum_value(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return value.value if hasattr(value, "value") else str(value)


def iso(value: Any) -> str | None:
    return value.isoformat() if value else None


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(result) or math.isinf(result):
        return default
    return result


def score_bucket(score: Any) -> str:
    numeric = as_float(score)
    if numeric >= 85:
        return "CRITICAL"
    if numeric >= 65:
        return "HIGH"
    if numeric >= 40:
        return "MEDIUM"
    return "LOW"


def _severity_sort_key(finding: Finding) -> tuple[int, float, str]:
    severity = enum_value(finding.severity, "LOW").upper()
    return (_SEVERITY_RANK.get(severity, 99), -as_float(finding.composite_score), finding.title or "")


def sanitize_filename_component(value: str | None, fallback: str = "assessment") -> str:
    candidate = (value or fallback).strip() or fallback
    candidate = _SAFE_FILENAME_RE.sub("-", candidate).strip("-._")
    return candidate[:96] or fallback


def normalize_report_sections(requested: Iterable[str] | None) -> dict[str, Any]:
    raw = [str(section or "").strip() for section in (requested or []) if str(section or "").strip()]
    if not raw:
        included = list(DEFAULT_REPORT_SECTIONS)
        return {
            "requested": [],
            "included": included,
            "ignored": [],
            "used_defaults": True,
        }

    included: list[str] = []
    ignored: list[str] = []
    for original in raw:
        canonical = SECTION_ALIASES.get(original, original)
        if canonical not in _SECTION_ID_SET:
            ignored.append(original)
            continue
        if canonical not in included:
            included.append(canonical)

    if not included:
        included = list(DEFAULT_REPORT_SECTIONS)
    return {
        "requested": raw,
        "included": included,
        "ignored": ignored,
        "used_defaults": not bool(raw) or not bool([item for item in raw if SECTION_ALIASES.get(item, item) in _SECTION_ID_SET]),
    }


def _truncate_text(value: Any, limit: int = 280) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\x00", " ").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _sensitive_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in _SAFE_KEY_EXCEPTIONS:
        return False
    return any(token in lowered for token in _SENSITIVE_KEY_TOKENS)


def redact_sensitive(value: Any, *, key: str | None = None, depth: int = 0, _seen: frozenset[int] | None = None) -> Any:
    """Return a bounded, redacted representation safe for reports.

    Reports need to prove that evidence exists without becoming a credential
    warehouse. Keys that are likely to contain secrets are replaced, deeply nested
    objects are summarized, and large collections are trimmed with explicit markers.
    """
    if _seen is None:
        _seen = frozenset()
    if key and _sensitive_key(key):
        return "[REDACTED:SENSITIVE]"
    if depth >= 4:
        return "[TRUNCATED:DEPTH]"
    if isinstance(value, (dict, list, tuple)) and id(value) in _seen:
        return "[CIRCULAR_REFERENCE]"
    _seen = _seen | {id(value)}
    if isinstance(value, dict):
        rendered: dict[str, Any] = {}
        items = list(value.items())
        for _idx, (child_key, child_value) in enumerate(items[:20]):
            rendered[str(child_key)] = redact_sensitive(child_value, key=str(child_key), depth=depth + 1, _seen=_seen)
        if len(items) > 20:
            rendered["__truncated_keys__"] = len(items) - 20
        return rendered
    if isinstance(value, list):
        rendered_list = [redact_sensitive(item, depth=depth + 1, _seen=_seen) for item in value[:15]]
        if len(value) > 15:
            rendered_list.append(f"[TRUNCATED:{len(value) - 15}_MORE_ITEMS]")
        return rendered_list
    if isinstance(value, tuple):
        return redact_sensitive(list(value), depth=depth, _seen=_seen)
    if isinstance(value, bytes):
        return f"[BINARY:{len(value)}_BYTES]"
    if isinstance(value, str):
        return _truncate_text(value, 360)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _truncate_text(value, 360)


def _edge_type_counts(edges: list[GraphEdge]) -> dict[str, int]:
    counts = Counter(enum_value(edge.edge_type, "UNKNOWN") for edge in edges)
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _entity_type_counts(entities: list[Entity]) -> dict[str, int]:
    counts = Counter(enum_value(entity.entity_type, "UNKNOWN") for entity in entities)
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _module_counts(findings: list[Finding]) -> list[dict[str, Any]]:
    counts = Counter((finding.module or "Unknown") for finding in findings)
    return [
        {"module": module, "total": total}
        for module, total in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]



_RISK_THEME_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "AD CS / Certificate Abuse",
        (
            "adcs", "pki", "certificate", "cert template", "esc1", "esc2", "esc3", "esc4",
            "enrollment agent", "manager approval",
        ),
    ),
    (
        "Replication / DCSync",
        ("dcsync", "replicat", "getchanges", "replication right", "directory changes"),
    ),
    (
        "Delegation & Kerberos Exposure",
        (
            "kerberoast", "as-rep", "asrep", "delegation", "rbcd", "unconstrained", "constrained",
            "spn", "service ticket", "kerberos",
        ),
    ),
    (
        "Credential Exposure & Secrets",
        (
            "password", "credential", "secret", "gpp", "cpassword", "cleartext", "hash", "ntlm",
            "loot", "sysvol",
        ),
    ),
    (
        "Privileged Access & ACL Control",
        (
            "acl", "writedacl", "writeowner", "genericall", "genericwrite", "owner", "adminsdholder",
            "domain admins", "enterprise admins", "privilege", "tier0", "tier-0", "shadow group",
        ),
    ),
    (
        "Trust Boundary & Forest Risk",
        ("trust", "sid filtering", "selective auth", "forest", "external domain", "cross-domain"),
    ),
    (
        "Identity Hygiene & Account Lifecycle",
        (
            "stale", "inactive", "password never expires", "preauth", "lockout", "disabled", "enabled",
            "account", "user hygiene", "maq", "machineaccountquota",
        ),
    ),
    (
        "Lateral Movement & Host Exposure",
        ("smb", "share", "local admin", "admin to", "rdp", "winrm", "session", "computer"),
    ),
    (
        "Persistence & Policy Abuse",
        ("persistence", "gpo", "scheduled task", "startup script", "logon script", "registry", "policy"),
    ),
)


def _finding_blob(finding: Finding, detail: dict[str, Any] | None = None) -> str:
    detail = detail or {}
    values = [
        finding.title or "",
        finding.finding_type or "",
        finding.module or "",
        detail.get("description", ""),
        detail.get("root_cause", ""),
        detail.get("remediation", ""),
    ]
    return " ".join(str(value or "") for value in values).lower()


def _themes_for_finding(finding: Finding, detail: dict[str, Any] | None = None) -> list[str]:
    blob = _finding_blob(finding, detail)
    themes = [label for label, tokens in _RISK_THEME_RULES if any(token in blob for token in tokens)]
    return themes[:3] or ["General Exposure / Needs Classification"]


def _risk_theme_summary(
    findings: list[Finding],
    details: list[dict[str, Any]],
    theme_index: dict[str, list[str]],
) -> dict[str, Any]:
    detail_map = {str(item.get("id")): item for item in details}
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        finding_id = str(finding.id)
        themes = theme_index.get(finding_id) or _themes_for_finding(finding, detail_map.get(finding_id))
        for theme in themes:
            grouped[theme].append(finding)

    items: list[dict[str, Any]] = []
    unique_findings: set[str] = set()
    for theme, theme_findings in grouped.items():
        unique_findings.update(str(finding.id) for finding in theme_findings)
        severity_counts = _severity_counts(theme_findings)
        sorted_findings = sorted(theme_findings, key=_severity_sort_key)
        max_score = max((as_float(finding.composite_score, 0.0) for finding in theme_findings), default=0.0)
        items.append(
            {
                "theme": theme,
                "finding_count": len(theme_findings),
                "critical_high_count": severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0),
                "severity_counts": severity_counts,
                "max_score": max_score,
                "top_findings": [
                    {
                        "id": str(finding.id),
                        "title": finding.title,
                        "severity": enum_value(finding.severity, "LOW"),
                        "score": as_float(finding.composite_score, 0.0),
                    }
                    for finding in sorted_findings[:5]
                ],
            }
        )
    items.sort(key=lambda item: (-int(item["critical_high_count"]), -int(item["finding_count"]), -as_float(item["max_score"]), item["theme"]))
    return {
        "theme_count": len(items),
        "unique_findings_covered": len(unique_findings),
        "themes": items,
        "classification_policy": "Themes are deterministic report labels derived from finding metadata; they organize risk and do not replace the source finding type.",
    }


def _coverage_assurance(
    findings: list[Finding],
    register: list[dict[str, Any]],
    details: list[dict[str, Any]],
    evidence_map: dict[str, list[dict[str, Any]]],
    modules_run: Iterable[str],
    included_sections: set[str],
) -> dict[str, Any]:
    finding_ids = {str(finding.id) for finding in findings}
    register_ids = {str(item.get("id")) for item in register if item.get("id")}
    detail_ids = {str(item.get("id")) for item in details if item.get("id")}
    missing_register = sorted(finding_ids - register_ids)
    missing_details = sorted(finding_ids - detail_ids)
    omitted = sorted(set(missing_register) | set(missing_details))
    detail_map = {str(item.get("id")): item for item in details}

    missing_description = []
    missing_remediation = []
    missing_root_cause = []
    without_evidence = []
    module_rows: dict[str, dict[str, Any]] = {}
    modules_with_findings: set[str] = set()
    for finding in findings:
        finding_id = str(finding.id)
        detail = detail_map.get(finding_id, {})
        module = finding.module or "Unknown"
        modules_with_findings.update(_source_module_ids_for_finding_module(module))
        module_row = module_rows.setdefault(
            module,
            {
                "module": module,
                "findings": 0,
                "critical_high": 0,
                "evidence_linked": 0,
                "remediation_ready": 0,
            },
        )
        module_row["findings"] += 1
        if enum_value(finding.severity, "LOW") in {"CRITICAL", "HIGH"}:
            module_row["critical_high"] += 1
        if evidence_map.get(finding_id):
            module_row["evidence_linked"] += 1
        else:
            without_evidence.append(finding_id)
        if detail.get("description"):
            pass
        else:
            missing_description.append(finding_id)
        if detail.get("root_cause"):
            pass
        else:
            missing_root_cause.append(finding_id)
        if detail.get("remediation") or detail.get("remediation_steps"):
            module_row["remediation_ready"] += 1
        else:
            missing_remediation.append(finding_id)

    module_coverage = sorted(module_rows.values(), key=lambda item: (-int(item["findings"]), item["module"]))
    linked = max(0, len(findings) - len(without_evidence))
    all_report_payloads_present = not omitted
    register_selected = "finding_register" in included_sections
    details_selected = "detailed_findings" in included_sections
    rendering_guarantee = register_selected and details_selected
    status = "PASS" if all_report_payloads_present else "ATTENTION"
    return {
        "integrity_status": status,
        "all_findings_present_in_payload": all_report_payloads_present,
        "selected_output_renders_complete_register_and_details": rendering_guarantee,
        "finding_count_reconciliation": {
            "stored_findings": len(findings),
            "finding_register_rows": len(register),
            "detailed_finding_rows": len(details),
            "unreported_payload_rows": len(omitted),
        },
        "unreported_finding_ids": omitted,
        "missing_register_ids": missing_register,
        "missing_detail_ids": missing_details,
        "linked_evidence_findings": linked,
        "findings_without_linked_evidence": without_evidence,
        "findings_without_description": missing_description,
        "findings_without_root_cause": missing_root_cause,
        "findings_without_remediation": missing_remediation,
        "evidence_linkage_pct": round((linked / len(findings) * 100.0), 1) if findings else 100.0,
        "module_coverage": module_coverage,
        "modules_run_without_findings": sorted(
            str(module)
            for module in modules_run
            if str(module) and _module_key(module) not in modules_with_findings
        ),
        "coverage_statement": "PASS means every stored finding is represented in the export payload register and detailed finding dossier. Output sections still follow the analyst's section selection.",
    }


def _confidence_bucket(value: float) -> str:
    if value >= 0.85:
        return "HIGH"
    if value >= 0.55:
        return "MEDIUM"
    return "LOW"


def _data_quality_summary(
    findings: list[Finding],
    evidence_records: list[EvidenceRecord],
    evidence_map: dict[str, list[dict[str, Any]]],
    coverage: dict[str, Any],
) -> dict[str, Any]:
    confidence_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    confidences: list[float] = []
    for finding in findings:
        confidence = as_float(finding.confidence, 0.0)
        confidences.append(confidence)
        confidence_counts[_confidence_bucket(confidence)] += 1
    average_confidence = round(sum(confidences) / len(confidences), 3) if confidences else 0.0
    linked_findings = int(coverage.get("linked_evidence_findings", 0))
    evidence_linkage_pct = as_float(coverage.get("evidence_linkage_pct"), 100.0)
    corroborated = sum(1 for record in evidence_records if bool(record.is_corroborated))
    corroborated_pct = round((corroborated / len(evidence_records) * 100.0), 1) if evidence_records else 0.0
    description_ready = max(0, len(findings) - len(coverage.get("findings_without_description", [])))
    remediation_ready = max(0, len(findings) - len(coverage.get("findings_without_remediation", [])))
    description_pct = round(description_ready / len(findings) * 100.0, 1) if findings else 100.0
    remediation_pct = round(remediation_ready / len(findings) * 100.0, 1) if findings else 100.0
    readiness_score = round(
        0.40 * evidence_linkage_pct
        + 25.0 * average_confidence
        + 0.15 * description_pct
        + 0.15 * remediation_pct
        + 0.05 * corroborated_pct,
        1,
    )
    readiness_grade = "A" if readiness_score >= 90 else "B" if readiness_score >= 75 else "C" if readiness_score >= 55 else "D"
    return {
        "readiness_score": min(100.0, readiness_score),
        "readiness_grade": readiness_grade,
        "average_finding_confidence": average_confidence,
        "confidence_counts": confidence_counts,
        "evidence_records": len(evidence_records),
        "corroborated_evidence_records": corroborated,
        "corroborated_evidence_pct": corroborated_pct,
        "findings_with_linked_evidence": linked_findings,
        "finding_evidence_linkage_pct": evidence_linkage_pct,
        "description_ready_pct": description_pct,
        "remediation_ready_pct": remediation_pct,
        "origin_counts": _origin_counts(findings),
        "evidence_origin_counts": _evidence_origin_counts(evidence_records),
        "quality_flags": {
            "missing_evidence": len(coverage.get("findings_without_linked_evidence", [])),
            "missing_description": len(coverage.get("findings_without_description", [])),
            "missing_root_cause": len(coverage.get("findings_without_root_cause", [])),
            "missing_remediation": len(coverage.get("findings_without_remediation", [])),
        },
        "scoring_note": "Readiness reflects reportability quality: finding confidence, evidence linkage, descriptive completeness, remediation completeness, and evidence corroboration.",
    }


def _priority_action_board(
    remediation_plan: dict[str, Any],
    theme_index: dict[str, list[str]],
) -> dict[str, Any]:
    items = list(remediation_plan.get("items", []))
    theme_lookup: dict[str, list[str]] = defaultdict(list)
    for finding_id, themes in theme_index.items():
        theme_lookup[str(finding_id)] = [str(theme) for theme in themes]

    waves = {
        "Immediate / 0-7 days": [],
        "Near-term / 8-30 days": [],
        "Planned / 31-90 days": [],
    }
    enriched: list[dict[str, Any]] = []
    for item in items:
        severity = str(item.get("severity") or "LOW")
        score = as_float(item.get("score"), 0.0)
        if severity == "CRITICAL" or score >= 85:
            wave = "Immediate / 0-7 days"
        elif severity == "HIGH" or score >= 65:
            wave = "Near-term / 8-30 days"
        else:
            wave = "Planned / 31-90 days"
        enriched_item = {
            **item,
            "wave": wave,
            "risk_themes": theme_lookup.get(str(item.get("finding_id") or ""), []),
        }
        waves[wave].append(enriched_item)
        enriched.append(enriched_item)
    return {
        "total_actions": len(enriched),
        "immediate_actions": len(waves["Immediate / 0-7 days"]),
        "near_term_actions": len(waves["Near-term / 8-30 days"]),
        "planned_actions": len(waves["Planned / 31-90 days"]),
        "waves": waves,
        "items": enriched,
        "planning_note": "Action waves are report prioritization guidance derived from current finding severity and score; they are not an execution authorization.",
    }

def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {enum_value(level): 0 for level in SeverityLevel}
    for finding in findings:
        key = enum_value(finding.severity, "LOW")
        counts[key] = counts.get(key, 0) + 1
    return counts


def _origin_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {enum_value(origin): 0 for origin in DataOrigin}
    for finding in findings:
        key = enum_value(finding.origin, DataOrigin.INFERRED.value)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _evidence_origin_counts(evidence_records: list[EvidenceRecord]) -> dict[str, int]:
    counts = {enum_value(origin): 0 for origin in DataOrigin}
    for evidence in evidence_records:
        key = enum_value(evidence.origin, DataOrigin.COLLECTED.value)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _status_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {enum_value(status): 0 for status in FindingStatus}
    for finding in findings:
        key = enum_value(finding.status, FindingStatus.OPEN.value)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _serialize_evidence(
    record: EvidenceRecord,
    *,
    relevance: str | None = None,
    relation_type: str | None = None,
    evidence_strength: str | None = None,
    source_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": str(record.id),
        "source_type": record.source_type or "unknown",
        "source_host": record.source_host,
        "source_port": record.source_port,
        "collection_method": record.collection_method,
        "collected_at": iso(record.collected_at),
        "origin": enum_value(record.origin, DataOrigin.COLLECTED.value),
        "confidence": as_float(record.confidence, 0.0),
        "is_corroborated": bool(record.is_corroborated),
        "relevance": relevance,
        "relation_type": relation_type or "supports",
        "evidence_strength": evidence_strength or "payload_level_fallback",
        "raw_data_redacted": redact_sensitive(record.raw_data or {}),
    }
    # Surface structured source refs (entity/edge/template/policy/trust) for reports
    if source_ref:
        inner_refs = source_ref.get("source_refs") or []
        if inner_refs:
            result["source_refs_summary"] = _summarize_source_refs(inner_refs)
    return result


def _summarize_source_refs(source_refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a safe, concise summary of structured source refs for report display."""
    summary: list[dict[str, Any]] = []
    for ref in source_refs[:10]:
        ref_type = ref.get("ref_type", "unknown")
        if ref_type == "edge":
            summary.append({
                "type": "edge",
                "edge_type": ref.get("edge_type"),
                "source": ref.get("source_name") or ref.get("source_id"),
                "target": ref.get("target_name") or ref.get("target_id"),
                "ace_right": ref.get("ace_right") or ref.get("rights"),
            })
        elif ref_type == "cert_template":
            summary.append({
                "type": "cert_template",
                "template_name": ref.get("template_name"),
                "ca_name": ref.get("ca_name"),
                "esc_flag": ref.get("esc_flag"),
                "enrollee_supplies_subject": ref.get("enrollee_supplies_subject"),
            })
        elif ref_type == "policy":
            attrs = {k: v for k, v in ref.items() if k not in ("ref_type", "finding_type") and v is not None}
            summary.append({"type": "policy", **attrs})
        elif ref_type == "trust":
            summary.append({
                "type": "trust",
                "partner": ref.get("partner"),
                "trust_type": ref.get("trust_type"),
                "direction": ref.get("direction"),
                "sid_filtering": ref.get("sid_filtering"),
            })
        elif ref_type == "entity":
            summary.append({
                "type": "entity",
                "sam_account_name": ref.get("sam_account_name"),
                "display_name": ref.get("display_name"),
                "object_sid": ref.get("object_sid"),
                "entity_type": ref.get("entity_type"),
            })
    return summary


def _serialize_finding(
    finding: Finding,
    linked_evidence: list[dict[str, Any]] | None = None,
    *,
    detailed: bool = True,
) -> dict[str, Any]:
    evidence_items = linked_evidence or []
    base = {
        "id": str(finding.id),
        "finding_type": finding.finding_type,
        "module": finding.module,
        "title": finding.title,
        "severity": enum_value(finding.severity, "LOW"),
        "status": enum_value(finding.status, FindingStatus.OPEN.value),
        "origin": enum_value(finding.origin, DataOrigin.INFERRED.value),
        "composite_score": as_float(finding.composite_score, 0.0),
        "technical_severity": None if finding.technical_severity is None else as_float(finding.technical_severity),
        "reachability_score": None if finding.reachability_score is None else as_float(finding.reachability_score),
        "confidence": as_float(finding.confidence, 0.0),
        "asset_criticality": None if finding.asset_criticality is None else as_float(finding.asset_criticality),
        "breadth_score": None if finding.breadth_score is None else as_float(finding.breadth_score),
        "remediation_complexity": None if finding.remediation_complexity is None else as_float(finding.remediation_complexity),
        "affected_count": int(finding.affected_count or 0),
        "evidence_count": len(evidence_items),
        "fix_complexity": finding.fix_complexity,
        "estimated_effort": finding.estimated_effort,
        "first_seen": iso(finding.first_seen),
        "last_seen": iso(finding.last_seen),
        "created_at": iso(finding.created_at),
        "updated_at": iso(finding.updated_at),
        "drift_status": finding.drift_status,
        "waiver_owner": finding.waiver_owner,
        "waiver_expiry": iso(finding.waiver_expiry),
        "cve_ids": redact_sensitive(finding.cve_ids or []),
        "mitre_attack_ids": redact_sensitive(finding.mitre_attack_ids or []),
    }
    if not detailed:
        return base
    base.update(
        {
            "description": finding.description or "",
            "root_cause": finding.root_cause or "",
            "causal_chain": redact_sensitive(finding.causal_chain or []),
            "attack_path": redact_sensitive(finding.attack_path or []),
            "affected_objects": redact_sensitive(finding.affected_objects or []),
            "remediation": finding.remediation or "",
            "remediation_steps": redact_sensitive(finding.remediation_steps or []),
            "references": redact_sensitive(finding.references or []),
            "waiver_reason": finding.waiver_reason or "",
            "evidence": evidence_items,
        }
    )
    return base


def _serialize_path(path: ExposurePath) -> dict[str, Any]:
    score = as_float(path.path_score, 0.0)
    steps = path.path_steps or []
    return {
        "id": str(path.id),
        "source_entity_id": str(path.source_entity_id) if path.source_entity_id else None,
        "target_entity_id": str(path.target_entity_id) if path.target_entity_id else None,
        "hop_count": int(path.hop_count or 0),
        "path_score": score,
        "risk_level": score_bucket(score),
        "target_tier": path.target_tier,
        "path_type": path.path_type or "UNKNOWN",
        "explanation": path.explanation or "",
        "path_steps": redact_sensitive(steps),
        "created_at": iso(path.created_at),
    }


def _serialize_validation_run(run: ValidationRun) -> dict[str, Any]:
    return {
        "run_id": str(run.id),
        "module_id": run.module_id,
        "target": run.target,
        "requested_mode": run.requested_mode,
        "execution_mode": run.execution_mode,
        "status": run.status,
        "final_verdict": run.final_verdict,
        "risk_score": None if run.risk_score is None else as_float(run.risk_score),
        "confidence": run.confidence,
        "consensus_score": run.consensus_score,
        "evidence_quality_score": run.evidence_quality_score,
        "severity_projection": run.severity_projection,
        "summary": run.summary or "",
        "reasoning": redact_sensitive(run.reasoning_json or {}),
        "simulated": bool(run.simulated),
        "origin": run.origin or DataOrigin.SIMULATED.value,
        "created_at": iso(run.created_at),
        "completed_at": iso(run.completed_at),
    }


def _serialize_cert_template(template: CertTemplate) -> dict[str, Any]:
    vulnerable_flags = [
        name
        for name, active in (
            ("ESC1", template.esc1_vulnerable),
            ("ESC2", template.esc2_vulnerable),
            ("ESC3", template.esc3_vulnerable),
            ("ESC4", template.esc4_vulnerable),
        )
        if active
    ]
    return {
        "id": str(template.id),
        "name": template.name,
        "ca_name": template.ca_name,
        "distinguished_name": template.distinguished_name,
        "enrollee_supplies_subject": bool(template.enrollee_supplies_subject),
        "requires_manager_approval": bool(template.requires_manager_approval),
        "authorized_signatures_required": int(template.authorized_signatures_required or 0),
        "validity_period": template.validity_period,
        "renewal_period": template.renewal_period,
        "ekus": redact_sensitive(template.ekus or []),
        "enrollment_rights": redact_sensitive(template.enrollment_rights or []),
        "write_rights": redact_sensitive(template.write_rights or []),
        "esc_flags": vulnerable_flags,
        "vulnerable": bool(vulnerable_flags),
    }


def _trust_risk(attributes: dict[str, Any]) -> str:
    if attributes.get("sid_filtering") is False:
        return "HIGH"
    if attributes.get("selective_auth") is True:
        return "LOW"
    return "MEDIUM"


def _serialize_trust(entity: Entity) -> dict[str, Any]:
    attrs = entity.attributes or {}
    return {
        "id": str(entity.id),
        "source": entity.domain or "current-domain",
        "target": str(attrs.get("target_domain") or attrs.get("target") or attrs.get("partner") or entity.display_name or entity.sam_account_name or entity.id),
        "trust_type": str(attrs.get("trust_type", "TRUST")),
        "direction": str(attrs.get("direction", "BIDIRECTIONAL")),
        "sid_filtering": attrs.get("sid_filtering", True),
        "selective_auth": bool(attrs.get("selective_auth", False)),
        "transitive": attrs.get("transitive", True),
        "risk": _trust_risk(attrs),
        "notes": entity.distinguished_name or entity.display_name or "",
        "created_at": iso(entity.created_at),
    }


def _password_age_days(entity: Entity) -> int:
    if entity.password_last_set:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        return max(0, (now - entity.password_last_set).days)
    attrs = entity.attributes or {}
    try:
        return max(0, int(attrs.get("password_age_days", 0)))
    except (TypeError, ValueError):
        return 0


def _service_account_risk(entity: Entity, password_age_days: int) -> str:
    attrs = entity.attributes or {}
    if attrs.get("unconstrained_delegation") or entity.is_admin_count:
        return "CRITICAL"
    if attrs.get("kerberoastable") or attrs.get("asrep_roastable"):
        return "HIGH"
    if password_age_days > 365:
        return "MEDIUM"
    return "LOW"


def _serialize_service_account(entity: Entity) -> dict[str, Any]:
    attrs = entity.attributes or {}
    pwd_age = _password_age_days(entity)
    spns = attrs.get("spns", []) or []
    groups = attrs.get("privileged_groups", []) or []
    return {
        "id": str(entity.id),
        "sam_account_name": entity.sam_account_name or "",
        "display_name": entity.display_name or entity.sam_account_name or "",
        "domain": entity.domain,
        "entity_type": enum_value(entity.entity_type, EntityType.SERVICE_ACCOUNT.value),
        "tier": entity.tier,
        "is_enabled": bool(entity.is_enabled),
        "is_admin_count": bool(entity.is_admin_count),
        "is_sensitive": bool(entity.is_sensitive),
        "spn_count": len(spns) if isinstance(spns, list) else 1,
        "kerberoastable": bool(attrs.get("kerberoastable", bool(spns))),
        "asrep_roastable": bool(attrs.get("asrep_roastable", False)),
        "unconstrained_delegation": bool(attrs.get("unconstrained_delegation", False)),
        "constrained_delegation": bool(attrs.get("constrained_delegation", False)),
        "resource_based_delegation": bool(attrs.get("resource_based_delegation", False)),
        "password_age_days": pwd_age,
        "password_last_set": iso(entity.password_last_set),
        "last_logon": iso(entity.last_logon),
        "in_privileged_group": bool(groups) or bool(entity.is_admin_count),
        "privileged_group_count": len(groups) if isinstance(groups, list) else 1,
        "risk": _service_account_risk(entity, pwd_age),
    }


def _serialize_execution_summary(chains: list[AttackChain]) -> dict[str, Any]:
    status_counts = Counter(str(chain.status or "UNKNOWN") for chain in chains)
    loot_counts: Counter[str] = Counter()
    chains_with_loot = 0
    for chain in chains:
        loot = chain.loot or {}
        if loot:
            chains_with_loot += 1
        for loot_type, items in loot.items():
            if isinstance(items, list):
                loot_counts[str(loot_type)] += len(items)
            elif items is not None:
                loot_counts[str(loot_type)] += 1
    return {
        "chain_count": len(chains),
        "status_counts": dict(sorted(status_counts.items(), key=lambda item: (-item[1], item[0]))),
        "chains_with_loot": chains_with_loot,
        "loot_item_counts_by_type": dict(sorted(loot_counts.items(), key=lambda item: (-item[1], item[0]))),
        "redaction_notice": "Operational loot values are intentionally omitted from assessment reports; only counts and types are retained.",
    }


def _assessment_payload(assessment: Assessment, score: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(assessment.id),
        "name": assessment.name,
        "domain": assessment.domain,
        "dc_ip": assessment.dc_ip,
        "status": enum_value(assessment.status),
        "collection_mode": enum_value(assessment.collection_mode),
        "created_at": iso(assessment.created_at),
        "started_at": iso(assessment.started_at),
        "completed_at": iso(assessment.completed_at),
        "modules_run": assessment.modules_run or [],
        "progress_pct": int(assessment.progress_pct or 0),
        "last_message": assessment.last_message,
        "exposure_score": score.get("score", assessment.exposure_score or 0.0),
        "rating": score.get("rating", "UNKNOWN"),
    }


def _risk_analysis_payload(score: dict[str, Any], findings: list[Finding], entities: list[Entity], edges: list[GraphEdge]) -> dict[str, Any]:
    return {
        "graph_backed": True,
        **score,
        "inputs": {
            "finding_count": len(findings),
            "entity_count": len(entities),
            "edge_count": len(edges),
        },
    }


def _finding_evidence_map(links: list[tuple[FindingEvidence, EvidenceRecord]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for link, evidence in links:
        result[str(link.finding_id)].append(
            _serialize_evidence(
                evidence,
                relevance=link.relevance,
                relation_type=link.relation_type,
                evidence_strength=getattr(link, "evidence_strength", None),
                source_ref=link.source_ref or {},
            )
        )
    return result


def _identity_inventory(entities: list[Entity]) -> dict[str, Any]:
    crown_jewels = [entity for entity in entities if bool(entity.is_crown_jewel)]
    tier0 = [entity for entity in entities if entity.tier == 0]
    admins = [entity for entity in entities if bool(entity.is_admin_count)]
    sensitive = [entity for entity in entities if bool(entity.is_sensitive)]
    protected = [entity for entity in entities if bool(entity.is_protected_user)]
    return {
        "entity_counts": _entity_type_counts(entities),
        "total_entities": len(entities),
        "tier0_entities": len(tier0),
        "crown_jewels": len(crown_jewels),
        "admin_count_entities": len(admins),
        "sensitive_entities": len(sensitive),
        "protected_users": len(protected),
        "tier0_examples": [
            {
                "id": str(entity.id),
                "label": entity.display_name or entity.sam_account_name or entity.dns_hostname or str(entity.id),
                "entity_type": enum_value(entity.entity_type, "UNKNOWN"),
                "crown_jewel": bool(entity.is_crown_jewel),
            }
            for entity in tier0[:20]
        ],
    }


def _graph_posture(entities: list[Entity], edges: list[GraphEdge]) -> dict[str, Any]:
    risk_weights = [as_float(edge.risk_weight, 0.0) for edge in edges]
    high_risk_edges = [edge for edge in edges if as_float(edge.risk_weight, 0.0) >= 0.8]
    return {
        "node_count": len(entities),
        "edge_count": len(edges),
        "edge_type_counts": _edge_type_counts(edges),
        "average_edge_risk_weight": round(sum(risk_weights) / len(risk_weights), 3) if risk_weights else 0.0,
        "high_risk_edge_count": len(high_risk_edges),
        "high_risk_edge_examples": [
            {
                "id": str(edge.id),
                "edge_type": enum_value(edge.edge_type, "UNKNOWN"),
                "risk_weight": as_float(edge.risk_weight, 0.0),
                "provenance": _truncate_text(edge.provenance, 160),
            }
            for edge in sorted(high_risk_edges, key=lambda item: -as_float(item.risk_weight, 0.0))[:20]
        ],
    }


def _path_summary(paths: list[ExposurePath]) -> dict[str, Any]:
    serialized = [_serialize_path(path) for path in paths]
    counts = Counter(path["risk_level"] for path in serialized)
    return {
        "total_paths": len(serialized),
        "risk_counts": {
            "CRITICAL": counts.get("CRITICAL", 0),
            "HIGH": counts.get("HIGH", 0),
            "MEDIUM": counts.get("MEDIUM", 0),
            "LOW": counts.get("LOW", 0),
        },
        "top_paths": serialized[:25],
    }


def _pki_summary(templates: list[CertTemplate]) -> dict[str, Any]:
    serialized = [_serialize_cert_template(template) for template in templates]
    return {
        "total_templates": len(serialized),
        "vulnerable_templates": sum(1 for item in serialized if item["vulnerable"]),
        "esc1_count": sum(1 for item in serialized if "ESC1" in item["esc_flags"]),
        "esc2_count": sum(1 for item in serialized if "ESC2" in item["esc_flags"]),
        "esc3_count": sum(1 for item in serialized if "ESC3" in item["esc_flags"]),
        "esc4_count": sum(1 for item in serialized if "ESC4" in item["esc_flags"]),
        "ca_names": sorted({item["ca_name"] for item in serialized if item.get("ca_name")}),
        "templates": serialized,
    }


def _trust_summary(trust_entities: list[Entity]) -> dict[str, Any]:
    trusts = [_serialize_trust(entity) for entity in trust_entities]
    return {
        "total_trusts": len(trusts),
        "sid_filtering_off": sum(1 for trust in trusts if not trust["sid_filtering"]),
        "selective_auth_off": sum(1 for trust in trusts if not trust["selective_auth"]),
        "forest_trusts": sum(1 for trust in trusts if "FOREST" in trust["trust_type"].upper()),
        "high_risk": sum(1 for trust in trusts if trust["risk"] == "HIGH"),
        "critical_risk": sum(1 for trust in trusts if trust["risk"] == "CRITICAL"),
        "trusts": trusts,
    }


def _service_account_summary(accounts: list[Entity]) -> dict[str, Any]:
    serialized_raw = [_serialize_service_account(entity) for entity in accounts]
    deduped: dict[tuple[str, str, str], dict[str, Any]] = {}

    def dedupe_key(account: dict[str, Any]) -> tuple[str, str, str]:
        name = account.get("sam_account_name") or account.get("display_name") or account.get("id")
        return (
            str(account.get("domain") or "").lower(),
            str(name or "").lower(),
            str(account.get("entity_type") or "").upper(),
        )

    def priority(account: dict[str, Any]) -> tuple[int, int, int, int, int]:
        risk_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
            str(account.get("risk") or "").upper(), 99
        )
        return (
            risk_rank,
            0 if account.get("kerberoastable") else 1,
            0 if account.get("asrep_roastable") else 1,
            0 if account.get("unconstrained_delegation") else 1,
            -int(account.get("spn_count") or 0),
        )

    for account in serialized_raw:
        key = dedupe_key(account)
        current = deduped.get(key)
        if current is None or priority(account) < priority(current):
            deduped[key] = account
    serialized = list(deduped.values())
    return {
        "total": len(serialized),
        "privileged": sum(1 for account in serialized if account["in_privileged_group"]),
        "kerberoastable": sum(1 for account in serialized if account["kerberoastable"]),
        "asrep_roastable": sum(1 for account in serialized if account["asrep_roastable"]),
        "unconstrained_delegation": sum(1 for account in serialized if account["unconstrained_delegation"]),
        "stale_password": sum(1 for account in serialized if account["password_age_days"] > 180),
        "by_risk": {
            "CRITICAL": sum(1 for account in serialized if account["risk"] == "CRITICAL"),
            "HIGH": sum(1 for account in serialized if account["risk"] == "HIGH"),
            "MEDIUM": sum(1 for account in serialized if account["risk"] == "MEDIUM"),
            "LOW": sum(1 for account in serialized if account["risk"] == "LOW"),
        },
        "accounts": serialized,
    }


def _validation_summary(runs: list[ValidationRun]) -> dict[str, Any]:
    serialized = [_serialize_validation_run(run) for run in runs]
    latest_by_module: dict[str, dict[str, Any]] = {}
    for item in serialized:
        latest_by_module.setdefault(item["module_id"], item)
    return {
        "total_runs": len(serialized),
        "simulated_runs": sum(1 for item in serialized if item["simulated"]),
        "completed_runs": sum(1 for item in serialized if item["status"] == "COMPLETED"),
        "latest_by_module": list(latest_by_module.values()),
        "runs": serialized[:100],
    }


def _remediation_plan(findings: list[Finding], details: list[dict[str, Any]]) -> dict[str, Any]:
    detail_map = {item["id"]: item for item in details}
    actionable = [finding for finding in findings if enum_value(finding.status, FindingStatus.OPEN.value) not in {FindingStatus.REMEDIATED.value, FindingStatus.FALSE_POSITIVE.value, FindingStatus.ACCEPTED.value}]
    ordered = sorted(
        actionable,
        key=lambda finding: (
            _STATUS_REMEDIATION_PRIORITY.get(enum_value(finding.status, FindingStatus.OPEN.value), 99),
            _SEVERITY_RANK.get(enum_value(finding.severity, "LOW"), 99),
            -as_float(finding.composite_score, 0.0),
            finding.title or "",
        ),
    )
    items: list[dict[str, Any]] = []
    for index, finding in enumerate(ordered, start=1):
        detail = detail_map.get(str(finding.id), _serialize_finding(finding, [], detailed=True))
        items.append(
            {
                "priority": index,
                "finding_id": str(finding.id),
                "title": finding.title,
                "severity": enum_value(finding.severity, "LOW"),
                "status": enum_value(finding.status, FindingStatus.OPEN.value),
                "score": as_float(finding.composite_score, 0.0),
                "estimated_effort": finding.estimated_effort or finding.fix_complexity or "unspecified",
                "remediation": detail.get("remediation", ""),
                "remediation_steps": detail.get("remediation_steps", []),
            }
        )
    return {
        "actionable_findings": len(actionable),
        "resolved_or_waived": max(0, len(findings) - len(actionable)),
        "items": items,
    }


def _evidence_appendix(records: list[EvidenceRecord]) -> dict[str, Any]:
    serialized = [_serialize_evidence(record) for record in records]
    counts_by_source = Counter(item["source_type"] for item in serialized)
    counts_by_method = Counter(item["collection_method"] or "unknown" for item in serialized)
    return {
        "total_records": len(serialized),
        "origin_counts": _evidence_origin_counts(records),
        "source_counts": dict(sorted(counts_by_source.items(), key=lambda item: (-item[1], item[0]))),
        "method_counts": dict(sorted(counts_by_method.items(), key=lambda item: (-item[1], item[0]))),
        "records": serialized,
        "redaction_policy": "Evidence previews redact likely credentials, tokens, hashes, tickets, private keys, and excessive nested payloads.",
    }


async def _load_evidence_links(
    db: AsyncSession,
    assessment_id: UUID,
    findings: list[Finding],
) -> tuple[list[EvidenceRecord], dict[str, list[dict[str, Any]]]]:
    evidence_records = (
        await db.execute(
            select(EvidenceRecord)
            .where(EvidenceRecord.assessment_id == assessment_id)
            .order_by(desc(EvidenceRecord.collected_at))
        )
    ).scalars().all()
    if not findings:
        return evidence_records, {}
    rows = (
        await db.execute(
            select(FindingEvidence, EvidenceRecord)
            .join(EvidenceRecord, FindingEvidence.evidence_id == EvidenceRecord.id)
            .where(FindingEvidence.finding_id.in_([finding.id for finding in findings]))
        )
    ).all()
    return evidence_records, _finding_evidence_map(rows)


async def build_report_payload(
    assessment_id: UUID,
    db: AsyncSession,
    current_user: PlatformUser,
    requested_sections: Iterable[str] | None = None,
) -> dict[str, Any]:
    section_state = normalize_report_sections(requested_sections)
    included = set(section_state["included"])
    assessment = await require_assessment_access(
        assessment_id,
        db,
        current_user,
        include_collection_config=True,
    )

    findings = (
        await db.execute(
            select(Finding)
            .where(Finding.assessment_id == assessment_id)
            .order_by(desc(Finding.composite_score).nullslast(), desc(Finding.created_at))
        )
    ).scalars().all()
    findings = sorted(findings, key=_severity_sort_key)
    entities = (
        await db.execute(select(Entity).where(Entity.assessment_id == assessment_id))
    ).scalars().all()
    edges = (
        await db.execute(select(GraphEdge).where(GraphEdge.assessment_id == assessment_id))
    ).scalars().all()

    analyzer = ADGraphAnalyzer()
    analyzer.load_from_db(entities, edges)
    score = RiskScoringService(analyzer).calculate_global_score(findings)

    # The report engine is an assurance surface, not a dashboard shortcut: evidence
    # linkage is always loaded so the coverage and quality ledgers can reconcile
    # every stored finding even when an analyst exports a smaller section subset.
    evidence_records, evidence_map = await _load_evidence_links(db, assessment_id, findings)

    findings_register = [_serialize_finding(finding, evidence_map.get(str(finding.id), []), detailed=False) for finding in findings]
    finding_details = [_serialize_finding(finding, evidence_map.get(str(finding.id), []), detailed=True) for finding in findings]
    detail_lookup = {str(item.get("id")): item for item in finding_details}
    theme_index = {
        str(finding.id): _themes_for_finding(finding, detail_lookup.get(str(finding.id)))
        for finding in findings
    }
    for item in findings_register:
        item["risk_themes"] = theme_index.get(str(item.get("id")), ["General Exposure / Needs Classification"])
    for item in finding_details:
        item["risk_themes"] = theme_index.get(str(item.get("id")), ["General Exposure / Needs Classification"])

    exposure_paths = []
    if "attack_paths" in included:
        exposure_paths = (
            await db.execute(
                select(ExposurePath)
                .where(ExposurePath.assessment_id == assessment_id)
                .order_by(desc(ExposurePath.path_score).nullslast(), ExposurePath.hop_count.asc().nullslast())
                .limit(250)
            )
        ).scalars().all()

    cert_templates = []
    if "pki_posture" in included:
        cert_templates = (
            await db.execute(select(CertTemplate).where(CertTemplate.assessment_id == assessment_id))
        ).scalars().all()

    trust_entities = []
    if "trust_posture" in included:
        trust_entities = [entity for entity in entities if enum_value(entity.entity_type) == EntityType.TRUST.value]

    service_accounts = []
    if "service_accounts" in included:
        service_account_types = {EntityType.SERVICE_ACCOUNT.value, EntityType.GMSA.value, EntityType.DMSA.value}
        service_accounts = [entity for entity in entities if enum_value(entity.entity_type) in service_account_types]

    validation_runs = []
    if "validation" in included:
        validation_runs = (
            await db.execute(
                select(ValidationRun)
                .where(ValidationRun.assessment_id == assessment_id)
                .order_by(desc(ValidationRun.created_at))
                .limit(200)
            )
        ).scalars().all()

    chains = []
    if "execution_summary" in included:
        chains = (
            await db.execute(
                select(AttackChain)
                .where(AttackChain.assessment_id == assessment_id)
                .order_by(desc(AttackChain.created_at))
                .limit(500)
            )
        ).scalars().all()

    top_findings = findings_register[:12]
    risk_analysis = _risk_analysis_payload(score, findings, entities, edges)
    assessment_payload = _assessment_payload(assessment, score)
    exposure = {
        "total_findings": len(findings),
        "severity_counts": _severity_counts(findings),
        "status_counts": _status_counts(findings),
        "origin_counts": _origin_counts(findings),
    }
    module_breakdown = _module_counts(findings)
    coverage_assurance = _coverage_assurance(
        findings,
        findings_register,
        finding_details,
        evidence_map,
        assessment_payload.get("modules_run", []),
        included,
    )
    data_quality = _data_quality_summary(findings, evidence_records, evidence_map, coverage_assurance)
    risk_theme_summary = _risk_theme_summary(findings, finding_details, theme_index)
    remediation_plan = _remediation_plan(findings, finding_details)
    priority_action_board = _priority_action_board(remediation_plan, theme_index)

    payload = {
        "report_meta": {
            "generator": "AdByG0d Reporting Engine",
            "generator_version": "1.0",
            "author": "White0xdi3",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sections": section_state,
            "available_sections": list(REPORT_SECTION_CATALOG),
            "provenance_policy": "COLLECTED and IMPORTED data are distinguished from INFERRED and SIMULATED conclusions throughout the report.",
            "redaction_policy": "Sensitive evidence values are summarized or redacted in exports instead of being printed verbatim.",
        },
        "assessment": assessment_payload,
        "risk_analysis": risk_analysis,
        "exposure": exposure,
        "entity_counts": _entity_type_counts(entities),
        "module_breakdown": module_breakdown,
        "coverage_assurance": coverage_assurance,
        "data_quality": data_quality,
        "risk_theme_summary": risk_theme_summary,
        "priority_action_board": priority_action_board,
        "top_findings": top_findings,
        "findings_register": findings_register,
        "finding_details": finding_details,
        "identity_inventory": _identity_inventory(entities),
        "graph_posture": _graph_posture(entities, edges),
        "attack_paths": _path_summary(exposure_paths),
        "pki_posture": _pki_summary(cert_templates),
        "trust_posture": _trust_summary(trust_entities),
        "service_account_posture": _service_account_summary(service_accounts),
        "validation_posture": _validation_summary(validation_runs),
        "remediation_plan": remediation_plan,
        "evidence_appendix": _evidence_appendix(evidence_records),
        "execution_summary": _serialize_execution_summary(chains),
        "raw_context": {
            "assessment_stats_redacted": redact_sensitive(assessment.stats or {}),
            "collection_config_redacted": redact_sensitive(assessment.collection_config or {}),
            "selection": section_state,
            "score_inputs": risk_analysis["inputs"],
        },
    }
    return payload


async def build_report_preview(
    assessment_id: UUID,
    db: AsyncSession,
    current_user: PlatformUser,
) -> dict[str, Any]:
    payload = await build_report_payload(
        assessment_id,
        db,
        current_user,
        requested_sections=(
            "exec_summary",
            "risk_posture",
            "coverage_assurance",
            "risk_themes",
            "priority_action_board",
            "data_quality",
            "finding_register",
        ),
    )
    # Keep the longstanding preview shape stable while exposing richer metadata for
    # the upgraded web page and external clients.
    return {
        "assessment": payload["assessment"],
        "risk_analysis": payload["risk_analysis"],
        "exposure": payload["exposure"],
        "entity_counts": payload["entity_counts"],
        "module_breakdown": payload["module_breakdown"],
        "coverage_assurance": payload["coverage_assurance"],
        "data_quality": payload["data_quality"],
        "risk_theme_summary": payload["risk_theme_summary"],
        "priority_action_board": payload["priority_action_board"],
        "top_findings": payload["top_findings"],
        "report_meta": payload["report_meta"],
        "available_sections": payload["report_meta"]["available_sections"],
    }
