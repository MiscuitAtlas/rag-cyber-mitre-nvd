import pytest
from conftest import FIXTURES, ROOT, SAMPLE, load_json

from rag_cyber.documents import (
    build_documents,
    chunk_documents,
    chunk_section,
    clean_text,
    cve_document,
    split_words,
    technique_document,
)
from rag_cyber.mitre import extract_techniques
from rag_cyber.nvd import extract_cves


def test_clean_text_removes_citations_and_keeps_technique_ids():
    text = "Abuse [Scheduled Task](https://attack.mitre.org/techniques/T1053/005) via [schtasks](https://attack.mitre.org/software/S0111).(Citation: X)\n\n  Use <code>at</code>."
    assert clean_text(text) == "Abuse Scheduled Task (T1053.005) via schtasks.\n\nUse at."


def test_split_words_overlap():
    windows = split_words([str(i) for i in range(10)], size=4, overlap=1)
    assert windows == [["0", "1", "2", "3"], ["3", "4", "5", "6"], ["6", "7", "8", "9"]]
    with pytest.raises(ValueError):
        split_words(["a"], size=3, overlap=3)


def test_chunk_section_packs_short_paragraphs_and_splits_long_ones():
    short = "one two\n\nthree four\n\nfive six"
    assert chunk_section(short, size=4, overlap=1) == ["one two three four", "five six"]
    long = " ".join(f"w{i}" for i in range(10))
    assert chunk_section(long, size=4, overlap=1)[0] == "w0 w1 w2 w3"


def test_technique_document_sections():
    techniques = {t["attack_id"]: t for t in extract_techniques(load_json(FIXTURES / "attack_bundle.json"))}
    doc = technique_document(techniques["T1053.005"])
    assert doc["doc_id"] == "mitre:T1053.005"
    sections = {s["name"]: s["text"] for s in doc["sections"]}
    assert list(sections) == ["Overview", "Description", "Detection", "Mitigations"]
    assert "Sub-technique of T1053 (Scheduled Task/Job)" in sections["Overview"]
    assert "Tactics: Execution, Persistence." in sections["Overview"]
    assert "DET0441" in sections["Overview"] and "M1028 Operating System Configuration" in sections["Overview"]
    assert "WinEventLog:Security (EventCode=4698) [Scheduled Job Creation]" in sections["Detection"]
    assert "(Citation" not in sections["Mitigations"]


def test_cve_document_uses_cwe_names_when_available():
    [cve] = [c for c in extract_cves(load_json(FIXTURES / "nvd_feed.json")) if c["cve_id"] == "CVE-2026-0001"]
    doc = cve_document(cve, {"CWE-79": "Cross-site Scripting"})
    overview = doc["sections"][0]["text"]
    assert "Severity: CRITICAL." in overview
    assert "CVSS base score: 9.8 (CVSS v3.1)." in overview
    assert "Weaknesses (CWE): CWE-79 (Cross-site Scripting), CWE-80." in overview
    assert "example:example_plugin" in overview


def test_every_chunk_starts_with_its_document_header(sample_chunks):
    for chunk in sample_chunks:
        header = chunk["text"].split("\n", 1)[0]
        assert header.endswith(f"| {chunk['section']}")
        identifier = chunk["metadata"].get("attack_id") or chunk["metadata"].get("cve_id")
        assert header.startswith(identifier)
    assert len({c["chunk_id"] for c in sample_chunks}) == len(sample_chunks)


def test_first_chunk_is_the_overview(sample_chunks):
    first = {}
    for chunk in sample_chunks:
        first.setdefault(chunk["doc_id"], chunk)
    assert {c["section"] for c in first.values()} == {"Overview"}


def test_sample_contains_detection_data_for_every_technique():
    techniques = load_json(SAMPLE / "mitre_techniques.json")
    assert len(techniques) == 50
    assert all(t["detection_strategies"] and t["tactics"] for t in techniques)


def test_sample_covers_every_evaluation_reference():
    documents = build_documents(load_json(SAMPLE / "mitre_techniques.json"), load_json(SAMPLE / "nvd_recent_cves.json"))
    doc_ids = {d["doc_id"] for d in documents}
    for question in load_json(ROOT / "data" / "eval" / "questions.json"):
        for ref in question["reference_ids"]:
            prefix = "cve" if ref.startswith("CVE") else "mitre"
            assert f"{prefix}:{ref}" in doc_ids, question["id"]


def test_chunk_documents_respects_size(sample_chunks):
    # en-tête (une ligne) + 120 mots au plus
    assert max(len(c["text"].split("\n", 1)[1].split()) for c in sample_chunks) <= 120
    assert chunk_documents([], 120, 30) == []
