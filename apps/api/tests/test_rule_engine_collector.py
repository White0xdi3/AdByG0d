from __future__ import annotations

import json
import zipfile
from io import BytesIO

import pytest
from sqlalchemy import select

from adbygod_api.core.analyzers.rule_engine import RuleEngine
from adbygod_api.core.parsers.bloodhound import BloodHoundParser
from adbygod_api.models import EdgeType
from adbygod_api.core.analyzers.collector_analyzer import build_rule_data_from_collector
from adbygod_api.models import Finding, FindingEvidence
from adbygod_api.schemas import CollectorIngest
from adbygod_api.routes import ingest as ingest_routes


def _entity(eid: str, etype: str, name: str, **overrides):
    data = {
        "id": eid,
        "object_sid": eid,
        "entity_type": etype,
        "sam_account_name": name,
        "display_name": name,
        "is_enabled": True,
        "is_admin_count": False,
        "is_crown_jewel": False,
        "tier": None,
        "attributes": {},
    }
    data.update(overrides)
    return data


def _edge(src: str, tgt: str, etype: str, **attrs):
    return {
        "source_id": src,
        "target_id": tgt,
        "edge_type": etype,
        "provenance": f"unit/{etype}",
        "attributes": attrs,
    }


def _rule_ids(data):
    return {m.rule_id for m in RuleEngine().evaluate_all(data)}


def _matches(data, finding_type: str):
    return [m for m in RuleEngine().evaluate_all(data) if m.finding_type == finding_type]


NEW_RULE_IDS = {
    "ADCS-005", "ADCS-007", "ADCS-009", "ADCS-010", "ADCS-011", "ADCS-013", "ADCS-016",
    "ACL-010", "SVC-002", "ACL-011", "PER-002", "ACL-012", "DEL-005", "SQL-001",
    "ADCS-017", "ADCS-018", "DNS-001", "NET-010", "HOST-001", "KRB-006",
    "USR-005", "PER-003", "USR-006", "TRUST-004",
}


def _rule_data_from_payload(payload: dict):
    return {
        "entities": payload.get("entities", []),
        "edges": payload.get("edges", []),
        "evidence": payload.get("evidence", []),
        "cert_templates": payload.get("cert_templates", []),
        "ca_flags": payload.get("ca_flags", []),
        "domain_info": (payload.get("metadata") or {}).get("domain_info", {}),
        "password_policy": (payload.get("metadata") or {}).get("password_policy", {}),
        "trusts": (payload.get("metadata") or {}).get("trusts", []),
        "network_config": (payload.get("metadata") or {}).get("network_config", {}),
    }


def _new_rule_count(rule_data: dict) -> int:
    return sum(1 for match in RuleEngine().evaluate_all(rule_data) if match.rule_id in NEW_RULE_IDS)


@pytest.fixture()
def generated_coverage_pack_dir(tmp_path):
    from scripts.generate_coverage_expansion_packs import write_coverage_expansion_packs

    pack_dir = tmp_path / "coverage_expansion"
    write_coverage_expansion_packs(pack_dir)
    return pack_dir


def test_new_edge_types_are_schema_values():
    for edge_type in [
        "READ_LAPS_PASSWORD", "READ_GMSA_PASSWORD", "WRITE_SPN",
        "ADD_KEY_CREDENTIAL_LINK", "WRITE_GP_LINK", "WRITE_ACCOUNT_RESTRICTIONS",
        "SQL_ADMIN", "HAS_SESSION", "MANAGE_CA", "MANAGE_CERTIFICATES",
        "CA_PRIVATE_KEY_CONTROL", "GOLDEN_CERT",
    ]:
        assert EdgeType(edge_type).value == edge_type


def test_bloodhound_parser_normalizes_new_edge_primitives():
    users = {
        "meta": {"type": "users", "version": 5},
        "data": [
            {
                "ObjectIdentifier": "S-1-5-21-1-1000",
                "Properties": {"name": "HELPDESK@LAB.LOCAL", "samaccountname": "helpdesk"},
            },
            {
                "ObjectIdentifier": "S-1-5-21-1-1100",
                "Properties": {"name": "VICTIM@LAB.LOCAL", "samaccountname": "victim"},
                "Aces": [
                    {"PrincipalSID": "S-1-5-21-1-1000", "RightName": "AddKeyCredentialLink", "IsInherited": False},
                    {"PrincipalSID": "S-1-5-21-1-1000", "RightName": "WriteSPN", "IsInherited": False},
                ],
            },
        ],
    }
    parsed = BloodHoundParser().parse_json(json.dumps(users).encode())
    edge_types = {edge["edge_type"] for edge in parsed["edges"]}
    assert "ADD_KEY_CREDENTIAL_LINK" in edge_types
    assert "WRITE_SPN" in edge_types


def test_edge_based_rules_fire_and_privileged_decoys_do_not():
    entities = [
        _entity("S-1-5-21-1-513", "GROUP", "Domain Users"),
        _entity("S-1-5-21-1-512", "GROUP", "Domain Admins", is_admin_count=True, tier=0, is_crown_jewel=True),
        _entity("S-1-5-21-1-2001", "COMPUTER", "TIER0-WS01$", tier=0, is_crown_jewel=True),
        _entity("S-1-5-21-1-3001", "USER", "svc-target"),
        _entity("S-1-5-21-1-4001", "GMSA", "web-gmsa$"),
        _entity("S-1-5-21-1-5001", "OU", "OU=Workstations"),
    ]
    edges = [
        _edge("S-1-5-21-1-513", "S-1-5-21-1-2001", "READ_LAPS_PASSWORD"),
        _edge("S-1-5-21-1-513", "S-1-5-21-1-4001", "READ_GMSA_PASSWORD"),
        _edge("S-1-5-21-1-513", "S-1-5-21-1-3001", "WRITE_SPN"),
        _edge("S-1-5-21-1-513", "S-1-5-21-1-3001", "ADD_KEY_CREDENTIAL_LINK"),
        _edge("S-1-5-21-1-513", "S-1-5-21-1-5001", "WRITE_GP_LINK"),
        _edge("S-1-5-21-1-513", "S-1-5-21-1-2001", "WRITE_ACCOUNT_RESTRICTIONS"),
        _edge("S-1-5-21-1-512", "S-1-5-21-1-3001", "ADD_KEY_CREDENTIAL_LINK"),
    ]
    ids = _rule_ids({"entities": entities, "edges": edges})
    assert {"ACL-010", "SVC-002", "ACL-011", "PER-002", "ACL-012", "DEL-005"} <= ids
    shadow = _matches({"entities": entities, "edges": edges}, "ADD_KEY_CREDENTIAL_LINK_ABUSE_PATH")[0]
    assert shadow.affected_count == 1
    assert shadow.affected_objects[0]["source_principal"] == "Domain Users"


def test_adcs_advanced_rules_fire_with_decoys():
    data = {
        "entities": [
            _entity("S-1-5-21-1-513", "GROUP", "Domain Users"),
            _entity("ca-1", "CA", "LAB-CA", distinguished_name="CN=LAB-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,DC=lab,DC=local"),
            _entity("ca-safe", "CA", "SAFE-CA"),
        ],
        "edges": [
            _edge("S-1-5-21-1-513", "ca-1", "WRITE_DACL"),
            _edge("S-1-5-21-1-513", "ca-1", "MANAGE_CA"),
            _edge("S-1-5-21-1-513", "ca-1", "MANAGE_CERTIFICATES"),
        ],
        "cert_templates": [
            {
                "name": "ESC9Tpl",
                "ca_name": "LAB-CA",
                "enrollment_rights": [{"principal_sid": "S-1-5-21-1-513", "principal_name": "Domain Users", "is_low_privileged": True}],
                "attributes": {"no_security_extension": True},
            },
            {
                "name": "ESC13Tpl",
                "ca_name": "LAB-CA",
                "enrollment_rights": [{"principal_sid": "S-1-5-21-1-513", "principal_name": "Domain Users", "is_low_privileged": True}],
                "attributes": {"issuance_policies": [{"oid": "1.2.3.4.5", "linked_group": "Domain Admins"}]},
            },
            {
                "name": "SafeTpl",
                "ca_name": "LAB-CA",
                "enrollment_rights": [{"principal_sid": "S-1-5-21-1-512", "principal_name": "Domain Admins"}],
                "attributes": {"no_security_extension": True},
            },
        ],
        "ca_flags": [
            {"ca_name": "LAB-CA", "strong_certificate_binding_enforcement": 0, "enforce_encrypt_icertrequest": False, "sid_security_extension_disabled": True},
            {"ca_name": "SAFE-CA", "strong_certificate_binding_enforcement": 2, "enforce_encrypt_icertrequest": True},
        ],
    }
    ids = _rule_ids(data)
    assert {"ADCS-005", "ADCS-007", "ADCS-009", "ADCS-010", "ADCS-011", "ADCS-013", "ADCS-016"} <= ids
    assert _matches(data, "ESC9_WEAK_SECURITY_EXTENSION_MAPPING")[0].affected_count == 1
    assert _matches(data, "ESC13_ISSUANCE_POLICY_GROUP_LINK")[0].affected_count == 1


def test_esc7_ignores_privileged_ca_permissions_from_ca_configs():
    matches = _matches({
        "entities": [],
        "edges": [],
        "ca_configs": [{
            "ca_name": "CA",
            "dangerous_permissions": [
                {"permission": "ManageCA", "principal_name": "Domain Admins"},
                {"permission": "ManageCertificates", "principal_name": "Enterprise Admins"},
            ],
        }],
    }, "ESC7_CA_PERMISSION_ABUSE")
    assert matches == []


def test_esc7_ignores_approved_pki_admin_principals_from_ca_configs():
    matches = _matches({
        "entities": [],
        "edges": [],
        "ca_configs": [{
            "ca_name": "CA",
            "approved_pki_admins": [
                "PKI Operations",
                {"name": "Explicit CA Managers"},
            ],
            "dangerous_permissions": [
                {"permission": "ManageCA", "principal_name": "PKI Operations"},
                {"permission": "ManageCertificates", "principal_name": "Explicit CA Managers"},
                {"permission": "ManageCA", "principal_name": "Certificate Admins"},
            ],
        }],
    }, "ESC7_CA_PERMISSION_ABUSE")
    assert matches == []


def test_esc7_still_flags_unapproved_ca_managers():
    matches = _matches({
        "entities": [],
        "edges": [],
        "ca_configs": [{
            "ca_name": "CA",
            "approved_pki_admins": ["PKI Operations"],
            "dangerous_permissions": [
                {"permission": "ManageCA", "principal_name": "Helpdesk"},
            ],
        }],
    }, "ESC7_CA_PERMISSION_ABUSE")
    assert len(matches) == 1
    assert matches[0].affected_count == 1


def test_esc13_requires_privileged_linked_group():
    data = {
        "cert_templates": [{
            "name": "NonPrivLinkedPolicy",
            "ca_name": "CA",
            "enrollment_rights": [{"principal_sid": "S-1-5-21-1-513", "principal_name": "Domain Users", "is_low_privileged": True}],
            "attributes": {"issuance_policies": [{"oid": "1.2.3.4", "linked_group": "VPN Users"}]},
        }],
    }
    assert _matches(data, "ESC13_ISSUANCE_POLICY_GROUP_LINK") == []


def test_esc13_uses_custom_privileged_group_metadata():
    data = {
        "metadata": {"privileged_groups": [{"name": "Crown Jewel Operators"}]},
        "cert_templates": [{
            "name": "CustomPrivLinkedPolicy",
            "ca_name": "CA",
            "enrollment_rights": [{"principal_sid": "S-1-5-21-1-513", "principal_name": "Domain Users", "is_low_privileged": True}],
            "attributes": {"issuance_policies": [{"oid": "1.2.3.4", "linked_group": "Crown Jewel Operators"}]},
        }],
    }
    matches = _matches(data, "ESC13_ISSUANCE_POLICY_GROUP_LINK")
    assert len(matches) == 1
    assert matches[0].affected_count == 1


def test_esc13_respects_explicit_nonprivileged_linked_group_metadata():
    data = {
        "cert_templates": [{
            "name": "ExplicitNonPrivLinkedPolicy",
            "ca_name": "CA",
            "enrollment_rights": [{"principal_sid": "S-1-5-21-1-513", "principal_name": "Domain Users", "is_low_privileged": True}],
            "attributes": {"issuance_policies": [{
                "oid": "1.2.3.4",
                "linked_group": {"name": "Application Admins", "is_privileged": False, "tier": 2},
            }]},
        }],
    }
    assert _matches(data, "ESC13_ISSUANCE_POLICY_GROUP_LINK") == []


def test_usr006_ignores_disabled_dollar_suffix_users():
    data = {"entities": [_entity("u1", "USER", "disabled$", is_enabled=False)]}
    assert _matches(data, "USER_ACCOUNT_DOLLAR_SUFFIX") == []


def test_esc5_does_not_duplicate_esc4_template_object_control():
    data = {
        "entities": [
            _entity("S-1-5-21-1-513", "GROUP", "Domain Users"),
            _entity(
                "tpl-1",
                "CERT_TEMPLATE",
                "WeakTemplate",
                distinguished_name="CN=WeakTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,DC=lab,DC=local",
            ),
        ],
        "edges": [_edge("S-1-5-21-1-513", "tpl-1", "WRITE_DACL")],
        "cert_templates": [{
            "name": "WeakTemplate",
            "write_rights": [{"principal_sid": "S-1-5-21-1-513", "is_low_privileged": True}],
            "esc4_vulnerable": True,
        }],
    }
    ids = _rule_ids(data)
    assert "ADCS-004" in ids
    assert "ADCS-005" not in ids


def test_collector_only_signals_are_centralized_with_false_positive_controls():
    entities = [
        _entity("u1", "USER", "alice", attributes={"description": "password=Spring2026!"}),
        _entity("u2", "USER", "backup$", attributes={}),
        _entity("u2-disabled", "USER", "disabled-backup$", is_enabled=False, attributes={}),
        _entity("u3", "USER", "hidden-admin", attributes={"primaryGroupID": "512"}),
        _entity("u4", "USER", "des-user", attributes={"use_des_key_only": True}),
        _entity("u5", "USER", "disabled-des", is_enabled=False, attributes={"use_des_key_only": True}),
        _entity("c1", "COMPUTER", "XP01$", attributes={"operating_system": "Windows XP"}),
        _entity("dns", "GROUP", "DNSAdmins"),
        _entity("du", "GROUP", "Domain Users"),
    ]
    data = {
        "entities": entities,
        "edges": [_edge("du", "dns", "MEMBER_OF")],
        "network_config": {"null_session_hosts": ["files01.lab.local"]},
        "trusts": [{"partner": "legacy.local", "trust_attributes": "64"}, {"partner": "safe.local", "trust_attributes": "4"}],
    }
    ids = _rule_ids(data)
    assert {"DNS-001", "NET-010", "HOST-001", "KRB-006", "USR-005", "PER-003", "USR-006", "TRUST-004"} <= ids
    assert _matches(data, "DES_ONLY_KERBEROS_ACCOUNT")[0].affected_count == 1


def test_bloodhound_zip_pack_imports_expanded_edges():
    payload = {
        "meta": {"type": "users", "version": 5},
        "data": [{
            "ObjectIdentifier": "S-1-5-21-1-9001",
            "Properties": {"name": "TARGET@LAB.LOCAL", "samaccountname": "target"},
            "Aces": [{"PrincipalSID": "S-1-5-21-1-513", "RightName": "ReadLAPSPassword", "IsInherited": False}],
        }],
    }
    bio = BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("users.json", json.dumps(payload))
    parsed = BloodHoundParser().parse_zip(bio.getvalue())
    assert any(edge["edge_type"] == "READ_LAPS_PASSWORD" for edge in parsed["edges"])


def test_native_collector_canonical_overlay_feeds_rule_engine():
    overlay = {
        "entities": [
            _entity("S-1-5-21-1-513", "GROUP", "Domain Users"),
            _entity("S-1-5-21-1-2001", "COMPUTER", "WS01$"),
        ],
        "edges": [_edge("S-1-5-21-1-513", "S-1-5-21-1-2001", "READ_LAPS_PASSWORD")],
        "network_config": {"null_session_hosts": ["fs01.lab.local"]},
    }
    rule_data = build_rule_data_from_collector({
        "coverage_expansion": {
            "commands": [],
            "canonical_overlay_schema": "adbygod.coverage_expansion.v1",
            "canonical": overlay,
        }
    })
    assert rule_data["edges"][0]["edge_type"] == "READ_LAPS_PASSWORD"
    ids = _rule_ids(rule_data)
    assert {"ACL-010", "NET-010"} <= ids


def test_native_collector_canonical_overlay_is_gated():
    overlay = {
        "entities": [
            _entity("S-1-5-21-1-513", "GROUP", "Domain Users"),
            _entity("S-1-5-21-1-2001", "COMPUTER", "WS01$"),
        ],
        "edges": [_edge("S-1-5-21-1-513", "S-1-5-21-1-2001", "READ_LAPS_PASSWORD")],
    }
    rule_data = build_rule_data_from_collector({"enum": {"commands": [], "canonical": overlay}})
    assert rule_data["edges"] == []
    assert "ACL-010" not in _rule_ids(rule_data)


def test_generated_coverage_expansion_packs_match_expected_counts(generated_coverage_pack_dir):
    pack_dir = generated_coverage_pack_dir
    expected = json.loads((pack_dir / "expected_findings.json").read_text())

    canonical = json.loads((pack_dir / "canonical_coverage_pack_fixture.json").read_text())
    assert _new_rule_count(_rule_data_from_payload(canonical)) == expected["canonical"]["total_new_rule_findings"]

    with zipfile.ZipFile(pack_dir / "native_collector_coverage_pack_fixture.zip") as zf:
        module = json.loads(zf.read("coverage_expansion.json"))
    native_rule_data = build_rule_data_from_collector({"coverage_expansion": module})
    assert _new_rule_count(native_rule_data) == expected["native_collector"]["total_new_rule_findings"]

    parsed = BloodHoundParser().parse_zip((pack_dir / "bloodhound_coverage_pack_fixture.zip").read_bytes())
    parsed["metadata"].setdefault("network_config", {})
    bh_rule_data = _rule_data_from_payload(parsed)
    assert _new_rule_count(bh_rule_data) == expected["bloodhound"]["total_new_rule_findings"]

    nightmare = BloodHoundParser().parse_zip((pack_dir / "bloodhound_coverage_nightmare_fixture.zip").read_bytes())
    nightmare["metadata"].setdefault("network_config", {})
    assert _new_rule_count(_rule_data_from_payload(nightmare)) == expected["nightmare"]["total_new_rule_findings"]


def test_generated_canonical_pack_ingests_with_evidence_and_report(test_app, generated_coverage_pack_dir):
    pack_dir = generated_coverage_pack_dir
    expected = json.loads((pack_dir / "expected_findings.json").read_text())
    canonical = json.loads((pack_dir / "canonical_coverage_pack_fixture.json").read_text())

    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("coverage-report", "coverage-report@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Coverage Expansion Report", "coverage.local", workspace_id=None, created_by=user.id))

    assert db.run(ingest_routes._process_ingest(assessment.id, CollectorIngest(**canonical))) is True

    async def _summary():
        async with test_app["session_maker"]() as session:
            findings = (await session.execute(select(Finding).where(Finding.assessment_id == assessment.id))).scalars().all()
            links = (await session.execute(select(FindingEvidence))).scalars().all()
            return findings, links

    findings, links = db.run(_summary())
    new_rule_findings = [finding for finding in findings if finding.finding_type in expected["canonical"]["by_finding_type"]]
    assert len(new_rule_findings) == expected["canonical"]["total_new_rule_findings"]
    assert len(links) >= len(new_rule_findings)

    response = client.post(
        "/api/v1/reports/export",
        headers=test_app["headers_for"](user),
        json={"assessment_id": str(assessment.id), "format": "json", "sections": ["finding_register", "detailed_findings", "coverage_assurance"]},
    )
    assert response.status_code == 200
    report = response.json()["payload"]
    titles = {item["title"] for item in report["findings_register"]}
    assert any("PKI object control" in title for title in titles)
    assert all(item["evidence_count"] > 0 for item in report["findings_register"])
