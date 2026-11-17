from conftest import FIXTURES, load_json

from rag_cyber.cwe import parse_cwe_catalog
from rag_cyber.ids import find_all_ids, find_lookup_ids
from rag_cyber.mitre import extract_techniques
from rag_cyber.nvd import extract_cves

# --- Identifiants ---------------------------------------------------------------------------------------------


def test_lookup_ids_keeps_every_id_in_order():
    question = "Compare t1053.005, CVE-2025-14037 and T1047, then cve-2025-14037 again."
    assert find_lookup_ids(question) == ["T1053.005", "CVE-2025-14037", "T1047"]


def test_lookup_ids_respects_boundaries():
    assert find_lookup_ids("AT1053 or T10530 or T1053.0055 or XCVE-2024-1234") == []
    assert find_lookup_ids("(T1053).") == ["T1053"]


def test_all_ids_include_cwe_detection_and_mitigation():
    text = "CWE-79, DET0441, M1028 and T1053.005; CWE-798 is different from CWE-79."
    assert find_all_ids(text) == ["CWE-79", "DET0441", "M1028", "T1053.005", "CWE-798"]


# --- MITRE ATT&CK ---------------------------------------------------------------------------------------------


def _techniques():
    return {t["attack_id"]: t for t in extract_techniques(load_json(FIXTURES / "attack_bundle.json"))}


def test_revoked_and_deprecated_techniques_are_skipped():
    assert set(_techniques()) == {"T1053", "T1053.005"}


def test_subtechnique_parent_tactics_and_platforms():
    tech = _techniques()["T1053.005"]
    assert tech["is_subtechnique"] is True
    assert (tech["parent_id"], tech["parent_name"]) == ("T1053", "Scheduled Task/Job")
    assert tech["tactics"] == ["Execution", "Persistence"]
    assert tech["platforms"] == ["Windows"]
    assert tech["url"] == "https://attack.mitre.org/techniques/T1053/005"


def test_only_mitre_attack_kill_chain_is_used():
    assert _techniques()["T1053"]["tactics"] == ["Execution"]


def test_detection_strategy_analytics_and_log_sources():
    [strategy] = _techniques()["T1053.005"]["detection_strategies"]
    assert (strategy["id"], strategy["name"]) == ("DET0441", "Detection of Suspicious Scheduled Task Creation")
    [analytic] = strategy["analytics"]  # analytique révoquée et référence absente ignorées
    assert analytic["id"] == "AN1221"
    assert analytic["log_sources"][0] == {
        "data_component": "Scheduled Job Creation",
        "name": "WinEventLog:Security",
        "channel": "EventCode=4698",
    }


def test_mitigations_skip_revoked_relationships():
    [mitigation] = _techniques()["T1053.005"]["mitigations"]
    assert mitigation["id"] == "M1028"
    assert mitigation["name"] == "Operating System Configuration"
    assert mitigation["description"].startswith("Force tasks")


def test_legacy_data_component_detection_is_kept():
    assert _techniques()["T1053"]["legacy_data_sources"] == ["Process Creation"]


# --- NVD ------------------------------------------------------------------------------------------------------


def _cves():
    return {c["cve_id"]: c for c in extract_cves(load_json(FIXTURES / "nvd_feed.json"))}


def test_rejected_cves_are_skipped():
    assert set(_cves()) == {"CVE-2026-0001", "CVE-2026-0002"}


def test_primary_cvss_is_preferred_over_secondary():
    cve = _cves()["CVE-2026-0001"]
    assert (cve["cvss_version"], cve["cvss_score"], cve["severity"]) == ("3.1", 9.8, "CRITICAL")
    assert cve["cvss_source"] == "nvd@nist.gov"


def test_cvss_v2_severity_is_read_at_metric_level():
    cve = _cves()["CVE-2026-0002"]
    assert (cve["cvss_version"], cve["cvss_score"], cve["severity"]) == ("2.0", 7.5, "HIGH")


def test_weaknesses_are_deduplicated_without_nvd_placeholders():
    assert _cves()["CVE-2026-0001"]["weaknesses"] == ["CWE-79", "CWE-80"]
    assert _cves()["CVE-2026-0002"]["weaknesses"] == []


def test_english_description_and_vulnerable_products():
    cve = _cves()["CVE-2026-0001"]
    assert cve["description"] == "Example plugin for WordPress is vulnerable to XSS."
    assert cve["products"] == ["example:example_plugin"]


# --- CWE ------------------------------------------------------------------------------------------------------


def test_cwe_catalog_keeps_active_weaknesses_only():
    names = parse_cwe_catalog(FIXTURES / "cwec_sample.xml")
    assert names == {
        "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "CWE-352": "Cross-Site Request Forgery (CSRF)",
    }
