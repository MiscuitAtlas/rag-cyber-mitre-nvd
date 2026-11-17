import json

from conftest import ROOT, load_json

from rag_cyber.evaluation import answer_facts, build_report, contains, run_mode, score_result, write_results


def test_contains_matches_whole_words_only():
    assert contains("l'outil at sous Linux", "At")
    assert not contains("MITRE ATT&CK catalogue", "At")
    assert contains("faiblesse CWE-79.", "CWE-79")
    assert not contains("faiblesse CWE-798", "CWE-79")
    assert contains("Scheduled Task/Job (T1053)", "Scheduled Task/Job")


def test_expected_severity_is_also_found_in_french():
    assert contains("La sévérité de cette CVE est moyenne.", "MEDIUM")
    assert contains("Gravité : MEDIUM", "MEDIUM")
    assert not contains("La sévérité de cette CVE est élevée.", "MEDIUM")


def test_answer_facts_are_normalized():
    answer = "La gravité de CVE-2024-13785 est MEDIUM, avec un score CVSS de 5,6 (CWE-94)."
    assert answer_facts(answer) == ["id:CVE-2024-13785", "id:CWE-94", "score:5.6", "severity:MEDIUM"]


def _result(answer, system="hybrid", context="", reference="", question="What is CVE-2024-13785?"):
    return {
        "id": "q",
        "category": "cve",
        "question": question,
        "expected_contains": ["MEDIUM", "CWE-94"],
        "reference_ids": ["CVE-2024-13785"],
        "reference_doc_ids": ["cve:CVE-2024-13785"],
        "reference_text": reference,
        "system": system,
        "retrieval_mode": "exact",
        "answer": answer,
        "latency_s": 1.0,
        "sources": [{"chunk_id": "cve:CVE-2024-13785#0", "doc_id": "cve:CVE-2024-13785", "score": 1.0, "text": context}]
        if context
        else [],
    }


REFERENCE = "CVE-2024-13785 | Overview\nSeverity: MEDIUM. CVSS base score: 5.6. Weaknesses (CWE): CWE-94."


def test_faithful_rag_answer():
    metrics = score_result(
        _result("Sévérité MEDIUM, score CVSS 5.6, faiblesse CWE-94 [S1].", context=REFERENCE, reference=REFERENCE)
    )
    assert metrics["coverage"] == 1.0
    assert metrics["faithfulness"] == 1.0
    assert metrics["context_recall"] == 1.0 and metrics["context_precision"] == 1.0
    assert metrics["hallucination"] is False


def test_llm_only_invented_facts_are_flagged():
    metrics = score_result(
        _result("Sévérité CRITICAL, score CVSS 9,8, faiblesse CWE-79.", system="llm_only", reference=REFERENCE)
    )
    assert metrics["coverage"] == 0.0
    assert metrics["hallucination"] is True
    assert metrics["hallucinated_facts"] == ["id:CWE-79", "score:9.8", "severity:CRITICAL"]
    assert "faithfulness" not in metrics and "context_precision" not in metrics


def test_unfaithful_but_true_fact_is_not_a_hallucination():
    # Fait absent du contexte transmis mais présent dans la base : infidèle au contexte, pas inventé.
    metrics = score_result(_result("CWE-94", context="CVE-2024-13785 | Description\nshortcode", reference=REFERENCE))
    assert metrics["faithfulness"] == 0.0
    assert metrics["hallucination"] is False
    assert metrics["context_recall"] == 0.0


def test_abstention_has_no_faithfulness_score():
    metrics = score_result(_result("Le contexte ne permet pas de répondre.", context=REFERENCE, reference=REFERENCE))
    assert metrics["faithfulness"] is None and metrics["hallucination"] is False


def test_v1_results_rescored_with_whole_words():
    """Les réponses de la v1 relues avec la nouvelle correspondance : seul le faux positif « At » du LLM seul disparaît."""
    scores = {}
    for name in ("rag_results", "llm_only_results"):
        rows = load_json(ROOT / "data" / "eval" / "v1" / f"{name}.json")
        scores[name] = sum(
            sum(contains(r["answer"], item) for item in r["expected_contains"]) / len(r["expected_contains"])
            for r in rows
        ) / len(rows)
    assert round(scores["rag_results"], 3) == 0.85
    assert round(scores["llm_only_results"], 3) == 0.375


def test_full_evaluation_run_and_report(tmp_path, pipeline):
    questions = (
        load_json(ROOT / "data" / "eval" / "questions.json")[:4]
        + load_json(ROOT / "data" / "eval" / "questions.json")[10:12]
    )
    info = {"ollama_model": "fake"}
    for system in ("hybrid", "llm_only"):
        write_results(run_mode(pipeline, questions, system), tmp_path, system, info)
    summaries, report = build_report(tmp_path)
    assert set(summaries) == {"hybrid", "llm_only"}
    assert summaries["hybrid"]["context_precision"] == 1.0  # chaque question cite son identifiant
    assert summaries["hybrid"]["retrieval_modes"] == {"exact": 6}
    assert summaries["llm_only"]["context_recall"] is None
    assert "| Couverture des éléments attendus |" in report
    assert (tmp_path / "rapport_evaluation.md").exists()
    assert json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))["hybrid"]["questions"] == 6
