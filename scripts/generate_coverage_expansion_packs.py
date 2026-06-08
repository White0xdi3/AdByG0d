from __future__ import annotations

import json
import sys
import zipfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API_SRC = ROOT / "apps" / "api" / "src"
if str(API_SRC) not in sys.path:
    sys.path.insert(0, str(API_SRC))

from adbygod_api.core.analyzers.rule_engine import RuleEngine
from adbygod_api.core.analyzers.collector_analyzer import build_rule_data_from_collector
from adbygod_api.core.parsers.bloodhound import BloodHoundParser


OUT = ROOT / "data" / "samples" / "coverage_expansion"
NEW_RULE_IDS = {
    "ADCS-005", "ADCS-007", "ADCS-009", "ADCS-010", "ADCS-011", "ADCS-013", "ADCS-016",
    "ACL-010", "SVC-002", "ACL-011", "PER-002", "ACL-012", "DEL-005", "SQL-001",
    "ADCS-017", "ADCS-018", "DNS-001", "NET-010", "HOST-001", "KRB-006",
    "USR-005", "PER-003", "USR-006", "TRUST-004",
}


def entity(eid: str, etype: str, name: str, **kw):
    data = {
        "id": eid,
        "entity_type": etype,
        "object_sid": eid if eid.startswith("S-") else None,
        "sam_account_name": name,
        "display_name": name,
        "domain": "coverage.local",
        "is_enabled": True,
        "is_admin_count": False,
        "is_sensitive": False,
        "is_protected_user": False,
        "tier": None,
        "is_crown_jewel": False,
        "business_tags": [],
        "attributes": {},
    }
    data.update(kw)
    return data


def edge(src: str, tgt: str, etype: str, **attrs):
    return {
        "source_id": src,
        "target_id": tgt,
        "edge_type": etype,
        "risk_weight": 0.9,
        "provenance": f"coverage-expansion/{etype}",
        "attributes": attrs,
    }


def canonical_payload(multiplier: int = 1) -> dict:
    entities = [
        entity("S-1-5-21-100-513", "GROUP", "Domain Users"),
        entity("S-1-5-21-100-512", "GROUP", "Domain Admins", is_admin_count=True, tier=0, is_crown_jewel=True),
        entity("S-1-5-21-100-7700", "GROUP", "Crown Jewel Operators", tier=0, is_crown_jewel=True),
        entity("S-1-5-21-100-1101", "USER", "alice", attributes={"description": "password=Spring2026!"}),
        entity("S-1-5-21-100-1102", "USER", "backup$", attributes={}),
        entity("S-1-5-21-100-1103", "USER", "hidden-admin", attributes={"primaryGroupID": "512"}),
        entity("S-1-5-21-100-1104", "USER", "des-user", attributes={"use_des_key_only": True}),
        entity("S-1-5-21-100-1199", "USER", "disabled-des", is_enabled=False, attributes={"use_des_key_only": True}),
        entity("S-1-5-21-100-2101", "COMPUTER", "TIER0-WS01$", tier=0, is_crown_jewel=True, attributes={"operating_system": "Windows Server 2022"}),
        entity("S-1-5-21-100-2102", "COMPUTER", "XP01$", attributes={"operating_system": "Windows XP"}),
        entity("S-1-5-21-100-3101", "GMSA", "web-gmsa$"),
        entity("S-1-5-21-100-4101", "OU", "OU=Workstations"),
        entity("S-1-5-21-100-5101", "GROUP", "DNSAdmins"),
        entity("ca-coverage", "CA", "COVERAGE-CA", distinguished_name="CN=COVERAGE-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,DC=coverage,DC=local", is_crown_jewel=True, tier=0),
        entity("ca-safe", "CA", "SAFE-CA", is_crown_jewel=True, tier=0),
    ]
    edges = [
        edge("S-1-5-21-100-513", "S-1-5-21-100-2101", "READ_LAPS_PASSWORD"),
        edge("S-1-5-21-100-513", "S-1-5-21-100-3101", "READ_GMSA_PASSWORD"),
        edge("S-1-5-21-100-513", "S-1-5-21-100-1101", "WRITE_SPN"),
        edge("S-1-5-21-100-513", "S-1-5-21-100-1101", "ADD_KEY_CREDENTIAL_LINK"),
        edge("S-1-5-21-100-513", "S-1-5-21-100-4101", "WRITE_GP_LINK"),
        edge("S-1-5-21-100-513", "S-1-5-21-100-2101", "WRITE_ACCOUNT_RESTRICTIONS"),
        edge("S-1-5-21-100-513", "S-1-5-21-100-2101", "SQL_ADMIN"),
        edge("S-1-5-21-100-513", "ca-coverage", "WRITE_DACL"),
        edge("S-1-5-21-100-513", "ca-coverage", "MANAGE_CA"),
        edge("S-1-5-21-100-513", "ca-coverage", "MANAGE_CERTIFICATES"),
        edge("S-1-5-21-100-513", "ca-coverage", "CA_PRIVATE_KEY_CONTROL"),
        edge("S-1-5-21-100-513", "ca-coverage", "GOLDEN_CERT"),
        edge("S-1-5-21-100-513", "S-1-5-21-100-5101", "MEMBER_OF"),
        edge("S-1-5-21-100-512", "ca-safe", "MANAGE_CA"),
    ]
    for idx in range(1, multiplier):
        host_id = f"S-1-5-21-100-9{idx:04d}"
        entities.append(entity(host_id, "COMPUTER", f"DECOY{idx:04d}$", attributes={"operating_system": "Windows 11"}))
        if idx % 3 == 0:
            edges.append(edge("S-1-5-21-100-513", host_id, "HAS_SESSION"))

    cert_templates = [
        {
            "name": "ESC9-NoSecurityExtension",
            "ca_name": "COVERAGE-CA",
            "ekus": ["1.3.6.1.5.5.7.3.2"],
            "enrollment_rights": [{"principal_sid": "S-1-5-21-100-513", "principal_name": "Domain Users", "is_low_privileged": True}],
            "write_rights": [],
            "attributes": {"no_security_extension": True},
        },
        {
            "name": "ESC13-IssuancePolicy",
            "ca_name": "COVERAGE-CA",
            "ekus": ["1.3.6.1.5.5.7.3.2"],
            "enrollment_rights": [{"principal_sid": "S-1-5-21-100-513", "principal_name": "Domain Users", "is_low_privileged": True}],
            "write_rights": [],
            "attributes": {"issuance_policies": [{"oid": "1.2.3.4.5.6", "linked_group": "Domain Admins"}]},
        },
        {
            "name": "ESC13-CustomPrivilegedPolicy",
            "ca_name": "COVERAGE-CA",
            "ekus": ["1.3.6.1.5.5.7.3.2"],
            "enrollment_rights": [{"principal_sid": "S-1-5-21-100-513", "principal_name": "Domain Users", "is_low_privileged": True}],
            "write_rights": [],
            "attributes": {"issuance_policies": [{"oid": "1.2.3.4.5.7", "linked_group": "Crown Jewel Operators"}]},
        },
        {
            "name": "SAFE-ESC13-ExplicitNonPrivPolicy",
            "ca_name": "SAFE-CA",
            "ekus": ["1.3.6.1.5.5.7.3.2"],
            "enrollment_rights": [{"principal_sid": "S-1-5-21-100-513", "principal_name": "Domain Users", "is_low_privileged": True}],
            "write_rights": [],
            "attributes": {"issuance_policies": [{
                "oid": "1.2.3.4.5.8",
                "linked_group": {"name": "Application Admins", "is_privileged": False, "tier": 2},
            }]},
        },
        {
            "name": "SAFE-PrivilegedOnly-NoSecurityExtension",
            "ca_name": "SAFE-CA",
            "ekus": ["1.3.6.1.5.5.7.3.2"],
            "enrollment_rights": [{"principal_sid": "S-1-5-21-100-512", "principal_name": "Domain Admins"}],
            "write_rights": [],
            "attributes": {"no_security_extension": True},
        },
    ]
    ca_flags = [{
        "ca_name": "COVERAGE-CA",
        "hostname": "ca01.coverage.local",
        "strong_certificate_binding_enforcement": 0,
        "enforce_encrypt_icertrequest": False,
        "rpc_enrollment_enabled": True,
        "sid_security_extension_disabled": True,
        "collection_method": "coverage_expansion/ca_flags",
        "approved_pki_admins": ["PKI Operations"],
        "dangerous_permissions": [
            {"permission": "ManageCA", "principal_name": "PKI Operations"},
            {"permission": "ManageCertificates", "principal_name": "Certificate Admins"},
        ],
    }]
    evidence = [
        {"id": "coverage-entities", "source_type": "synthetic", "collection_method": "coverage_expansion/entities", "origin": "IMPORTED", "raw_data": {"type": "users", "count": len(entities)}, "confidence": 1.0},
        {"id": "coverage-edges", "source_type": "synthetic", "collection_method": "coverage_expansion/edges", "origin": "IMPORTED", "raw_data": {"type": "edges", "count": len(edges)}, "confidence": 1.0},
        {"id": "coverage-adcs", "source_type": "synthetic", "collection_method": "coverage_expansion/adcs", "origin": "IMPORTED", "raw_data": {"type": "certtemplates", "count": len(cert_templates)}, "confidence": 1.0},
    ]
    return {
        "schema_version": "1.0",
        "tool": "AdByG0d Coverage Expansion Synthetic Pack",
        "collection_mode": "IMPORT",
        "domain": "coverage.local",
        "dc_ip": None,
        "collected_at": "2026-05-20T00:00:00Z",
        "collector_version": "coverage-expansion/1.0",
        "modules_run": ["coverage_expansion"],
        "entities": entities,
        "edges": edges,
        "evidence": evidence,
        "findings": [],
        "cert_templates": cert_templates,
        "ca_flags": ca_flags,
        "metadata": {
            "domain_info": {},
            "password_policy": {},
            "trusts": [{"partner": "legacy.coverage.local", "trust_attributes": "64"}, {"partner": "safe.coverage.local", "trust_attributes": "4"}],
            "network_config": {"null_session_hosts": ["files01.coverage.local"]},
            "privileged_groups": [{"name": "Crown Jewel Operators"}],
        },
    }


def bloodhound_bundle() -> dict[str, dict]:
    sid_low = "S-1-5-21-100-513"
    return {
        "groups.json": {"meta": {"type": "groups", "version": 5}, "data": [
            {"ObjectIdentifier": sid_low, "Properties": {"name": "DOMAIN USERS@COVERAGE.LOCAL", "samaccountname": "Domain Users"}},
            {"ObjectIdentifier": "S-1-5-21-100-512", "Properties": {"name": "DOMAIN ADMINS@COVERAGE.LOCAL", "samaccountname": "Domain Admins", "admincount": True}},
            {"ObjectIdentifier": "S-1-5-21-100-5101", "Properties": {"name": "DNSADMINS@COVERAGE.LOCAL", "samaccountname": "DNSAdmins"}, "Members": [{"ObjectIdentifier": sid_low}]},
        ]},
        "users.json": {"meta": {"type": "users", "version": 5}, "data": [
            {"ObjectIdentifier": "S-1-5-21-100-1101", "Properties": {"name": "ALICE@COVERAGE.LOCAL", "samaccountname": "alice", "description": "password=Spring2026!"}, "Aces": [
                {"PrincipalSID": sid_low, "RightName": "WriteSPN", "IsInherited": False},
                {"PrincipalSID": sid_low, "RightName": "AddKeyCredentialLink", "IsInherited": False},
            ]},
            {"ObjectIdentifier": "S-1-5-21-100-1102", "Properties": {"name": "BACKUP$@COVERAGE.LOCAL", "samaccountname": "backup$"}},
            {"ObjectIdentifier": "S-1-5-21-100-1104", "Properties": {"name": "DES-USER@COVERAGE.LOCAL", "samaccountname": "des-user", "use_des_key_only": True}},
        ]},
        "computers.json": {"meta": {"type": "computers", "version": 5}, "data": [
            {"ObjectIdentifier": "S-1-5-21-100-2101", "Properties": {"name": "TIER0-WS01.COVERAGE.LOCAL", "samaccountname": "TIER0-WS01$", "operatingsystem": "Windows Server 2022"}, "Aces": [
                {"PrincipalSID": sid_low, "RightName": "ReadLAPSPassword", "IsInherited": False},
                {"PrincipalSID": sid_low, "RightName": "WriteAccountRestrictions", "IsInherited": False},
                {"PrincipalSID": sid_low, "RightName": "SQLAdmin", "IsInherited": False},
            ]},
            {"ObjectIdentifier": "S-1-5-21-100-2102", "Properties": {"name": "XP01.COVERAGE.LOCAL", "samaccountname": "XP01$", "operatingsystem": "Windows XP"}},
        ]},
        "ous.json": {"meta": {"type": "ous", "version": 5}, "data": [
            {"ObjectIdentifier": "S-1-5-21-100-4101", "Properties": {"name": "OU=Workstations"}, "Aces": [{"PrincipalSID": sid_low, "RightName": "WriteGPLink", "IsInherited": False}]}
        ]},
        "certtemplates.json": {"meta": {"type": "certtemplates", "version": 5}, "data": [
            {"ObjectIdentifier": "tpl-esc9", "Properties": {"name": "ESC9-NoSecurityExtension", "caname": "COVERAGE-CA", "ekus": ["1.3.6.1.5.5.7.3.2"], "enrollmentrights": [{"principal_sid": sid_low, "principal_name": "Domain Users", "is_low_privileged": True}], "no_security_extension": True}},
            {"ObjectIdentifier": "tpl-esc13", "Properties": {"name": "ESC13-IssuancePolicy", "caname": "COVERAGE-CA", "ekus": ["1.3.6.1.5.5.7.3.2"], "enrollmentrights": [{"principal_sid": sid_low, "principal_name": "Domain Users", "is_low_privileged": True}], "issuance_policies": [{"oid": "1.2.3.4.5.6", "linked_group": "Domain Admins"}]}},
            {"ObjectIdentifier": "tpl-safe", "Properties": {"name": "SAFE-PrivOnly", "caname": "SAFE-CA", "enrollmentrights": [{"principal_sid": "S-1-5-21-100-512", "principal_name": "Domain Admins"}], "no_security_extension": True}},
        ]},
        "enterprisecas.json": {"meta": {"type": "enterprisecas", "version": 5}, "data": [
            {"ObjectIdentifier": "ca-coverage", "Properties": {"name": "COVERAGE-CA", "strong_certificate_binding_enforcement": 0, "enforce_encrypt_icertrequest": False, "rpc_enrollment_enabled": True, "sid_security_extension_disabled": True}, "Aces": [
                {"PrincipalSID": sid_low, "RightName": "WriteDacl", "IsInherited": False},
                {"PrincipalSID": sid_low, "RightName": "ManageCA", "IsInherited": False},
                {"PrincipalSID": sid_low, "RightName": "ManageCertificates", "IsInherited": False},
                {"PrincipalSID": sid_low, "RightName": "CAPrivateKeyControl", "IsInherited": False},
                {"PrincipalSID": sid_low, "RightName": "GoldenCert", "IsInherited": False},
            ]},
            {"ObjectIdentifier": "ca-safe", "Properties": {"name": "SAFE-CA", "strong_certificate_binding_enforcement": 2, "enforce_encrypt_icertrequest": True}},
        ]},
    }


def rule_counts_for(payload: dict) -> dict:
    rule_data = {
        "entities": payload["entities"],
        "edges": payload["edges"],
        "evidence": payload["evidence"],
        "cert_templates": payload["cert_templates"],
        "ca_flags": payload.get("ca_flags", []),
        "domain_info": payload["metadata"].get("domain_info", {}),
        "password_policy": payload["metadata"].get("password_policy", {}),
        "trusts": payload["metadata"].get("trusts", []),
        "network_config": payload["metadata"].get("network_config", {}),
    }
    return rule_counts_for_rule_data(rule_data)


def rule_counts_for_rule_data(rule_data: dict) -> dict:
    matches = [m for m in RuleEngine().evaluate_all(rule_data) if m.rule_id in NEW_RULE_IDS]
    return {
        "total_new_rule_findings": len(matches),
        "by_rule_id": dict(sorted(Counter(m.rule_id for m in matches).items())),
        "by_finding_type": dict(sorted(Counter(m.finding_type for m in matches).items())),
        "severity_distribution": dict(sorted(Counter(m.severity for m in matches).items())),
        "affected_counts_by_rule_id": {m.rule_id: m.affected_count for m in matches},
    }
def write_json(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def write_coverage_expansion_packs(out: Path = OUT) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    canonical = canonical_payload()
    write_json(out / "canonical_coverage_pack_fixture.json", canonical)

    native_manifest = {
        "generator": "AdByGod-Native-Collector",
        "domain": "coverage.local",
        "dc_ip": "192.0.2.10",
        "collected_at": "2026-05-20T00:00:00Z",
        "collector_version": "coverage-expansion/1.0",
        "modules": ["coverage_expansion"],
    }
    with zipfile.ZipFile(out / "native_collector_coverage_pack_fixture.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(native_manifest, indent=2))
        zf.writestr("coverage_expansion.json", json.dumps({
            "commands": [],
            "canonical_overlay_schema": "adbygod.coverage_expansion.v1",
            "canonical": canonical,
        }, indent=2))

    bh = bloodhound_bundle()
    with zipfile.ZipFile(out / "bloodhound_coverage_pack_fixture.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in bh.items():
            zf.writestr(name, json.dumps(payload, indent=2))

    nightmare = bloodhound_bundle()
    nightmare["computers.json"]["data"].extend(
        {"ObjectIdentifier": f"S-1-5-21-100-8{idx:04d}", "Properties": {"name": f"DECOY{idx:04d}.COVERAGE.LOCAL", "samaccountname": f"DECOY{idx:04d}$", "operatingsystem": "Windows 11"}}
        for idx in range(500)
    )
    with zipfile.ZipFile(out / "bloodhound_coverage_nightmare_fixture.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in nightmare.items():
            zf.writestr(name, json.dumps(payload))

    parsed_bh = BloodHoundParser().parse_zip((out / "bloodhound_coverage_pack_fixture.zip").read_bytes())
    bh_canonical = {
        **canonical,
        "entities": parsed_bh["entities"],
        "edges": parsed_bh["edges"],
        "evidence": parsed_bh["evidence"],
        "cert_templates": parsed_bh["cert_templates"],
        "metadata": {**parsed_bh.get("metadata", {}), "network_config": {}, "trusts": []},
        "ca_flags": [],
    }
    expected = {
        "canonical": rule_counts_for(canonical),
        "native_collector": rule_counts_for_rule_data(build_rule_data_from_collector({
            "coverage_expansion": {
                "commands": [],
                "canonical_overlay_schema": "adbygod.coverage_expansion.v1",
                "canonical": canonical,
            }
        })),
        "bloodhound": rule_counts_for(bh_canonical),
        "nightmare": {"decoy_computers": 500, **rule_counts_for(bh_canonical)},
    }
    write_json(out / "expected_findings.json", expected)
    write_json(out / "rule_matrix.json", {
        "supported_paths": {
            "canonical": sorted(NEW_RULE_IDS),
            "native_collector": sorted(NEW_RULE_IDS),
            "bloodhound": sorted(expected["bloodhound"]["by_rule_id"].keys()),
            "live_collector": ["ADCS-005 collector-side exists", "ESC6 CA flags", "baseline LDAP/AD CS/template/ACL coverage; remaining CA settings require Windows CA config collector"],
        },
        "structural_limits": {
            "ESC12": "Not implemented: not enough project-defined scope/telemetry for a defensible rule.",
            "ESC14": "Schema-supported via cert template attributes, but no defensible rule added without validated telemetry semantics.",
            "ESC15": "Graph attack-flow reference exists; no central finding added without known template/application policy telemetry contract.",
        },
    })
    write_json(out / "decoy_manifest.json", {
        "decoys": [
            "SAFE-PrivilegedOnly-NoSecurityExtension has privileged-only enrollment and must not trigger ESC9.",
            "SAFE-CA has strong mapping/encrypted RPC and must not trigger ESC10/ESC11/ESC16.",
            "disabled-des has DES-only metadata but is disabled and must not count for KRB-006.",
            "Domain Admins ManageCA edge is privileged-source decoy and must not count for ESC7.",
            "Domain Admins and Enterprise Admins in CA dangerous_permissions must not trigger ESC7.",
            "PKI Operations and Certificate Admins in CA dangerous_permissions are approved PKI admins and must not trigger ESC7.",
            "Issuance policy linked to a non-privileged group must not trigger ESC13.",
            "SAFE-ESC13-ExplicitNonPrivPolicy has explicit nonprivileged linked-group metadata and must not trigger ESC13.",
            "Disabled user accounts ending in $ must not trigger USR-006.",
            "Certificate template object write control is covered by ESC4 and must not also trigger ESC5.",
            "NIGHTMARE DECOY hosts are Windows 11 and should not increase legacy OS findings.",
        ]
    })
    (out / "README.md").write_text(
        "# Coverage Expansion Synthetic Packs\n\n"
        "Import the `*_fixture.*` files through the product import UI or API.\n\n"
        "`expected_findings.json` contains exact expected new-rule finding row counts by import path. "
        "The BloodHound pack intentionally lacks network/trust-only posture signals, so its supported count is lower than canonical/native. "
        "Decoys are listed in `decoy_manifest.json` and should not create additional findings.\n",
        encoding="utf-8",
    )
    return expected


def main():
    expected = write_coverage_expansion_packs(OUT)
    print(f"Wrote coverage expansion packs to {OUT}")
    print(json.dumps(expected, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
