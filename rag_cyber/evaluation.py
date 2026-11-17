"""Évaluation : RAG (hybride, FAISS) contre LLM seul sur les questions de data/eval/questions.json.

Métriques, toutes calculées sans LLM juge (déterministes, recalculables à partir des fichiers de résultats) :

- couverture : part des éléments attendus présents dans la réponse (mot entier, sans tenir compte de la casse) ;
- rappel du contexte : part des éléments attendus présents dans les extraits transmis au LLM ;
- précision du contexte : part des extraits transmis qui proviennent du ou des documents de référence ;
- fidélité : part des faits vérifiables de la réponse (identifiants CVE/ATT&CK/CWE/DET/M, scores CVSS, sévérités)
  présents dans les extraits transmis ou dans la question ;
- taux d'hallucination : part des réponses fausses ou incomplètes données sans réserve, c'est-à-dire qui manquent un
  élément attendu absent de la question sans dire qu'elles ne savent pas, ou qui citent un fait vérifiable inventé ;
- abstentions : part des réponses incomplètes qui le signalent (« je ne peux pas répondre », « le contexte ne permet
  pas ») ;
- faits inventés : part des réponses citant un fait vérifiable absent à la fois de la question, des extraits transmis
  et des documents de référence de la base.

Ce sont des approximations par entités des métriques de RAGAS (Faithfulness, Context Precision/Recall) : elles ne
jugent pas les paraphrases, seulement les faits que l'on peut vérifier mécaniquement.
"""

from __future__ import annotations

import json
import re
import statistics
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rag_cyber.ids import find_all_ids

EVAL_MODES = ("hybrid", "faiss", "llm_only")

SEVERITIES = {
    "low": "LOW",
    "faible": "LOW",
    "basse": "LOW",
    "medium": "MEDIUM",
    "moyenne": "MEDIUM",
    "moyen": "MEDIUM",
    "modérée": "MEDIUM",
    "modéré": "MEDIUM",
    "high": "HIGH",
    "élevée": "HIGH",
    "élevé": "HIGH",
    "haute": "HIGH",
    "critical": "CRITICAL",
    "critique": "CRITICAL",
}
_SEVERITY_RE = re.compile(
    r"(?:s[ée]v[ée]rit[ée]|severity|criticit[ée]|gravit[ée])\W+(?:\w+\W+){0,6}?(" + "|".join(SEVERITIES) + r")\b",
    re.IGNORECASE,
)
_ABSTENTION_RE = re.compile(
    r"je ne (?:peux|sais) pas|ne (?:permet|contient|précise) pas|pas d'information|aucune information|n'existe pas"
    r"|n'a pas encore été|absents? de la base|aucun document|cannot answer|do not know|don't know",
    re.IGNORECASE,
)
_SCORE_RE = re.compile(r"(?:CVSS|score)[^0-9\n]{0,40}?\b(10(?:[.,]0)?|\d[.,]\d)\b", re.IGNORECASE)


# --- Correspondances -------------------------------------------------------------------------------------------


def contains(text: str, item: str) -> bool:
    """Mot ou expression entière : « At » ne correspond pas à « ATT&CK », « CWE-79 » pas à « CWE-798 »."""
    if re.search(rf"(?<!\w){re.escape(item)}(?!\w)", text, re.IGNORECASE):
        return True
    # Une sévérité attendue en anglais (« MEDIUM ») est aussi reconnue sous sa forme française (« moyenne »).
    target = SEVERITIES.get(item.lower())
    if target and item.upper() == target:
        return any(m.group(1) and SEVERITIES[m.group(1).lower()] == target for m in _SEVERITY_RE.finditer(text))
    return False


def answer_facts(answer: str) -> list[str]:
    """Faits vérifiables cités dans une réponse : identifiants, scores CVSS, sévérités (forme normalisée)."""
    facts = [f"id:{i}" for i in find_all_ids(answer)]
    facts += [f"score:{m.group(1).replace(',', '.')}" for m in _SCORE_RE.finditer(answer)]
    facts += [f"severity:{SEVERITIES[m.group(1).lower()]}" for m in _SEVERITY_RE.finditer(answer)]
    return list(dict.fromkeys(facts))


def is_abstention(answer: str) -> bool:
    """La réponse dit qu'elle ne peut pas répondre (entièrement ou en partie)."""
    return bool(_ABSTENTION_RE.search(answer.replace("’", "'")))


def fact_supported(fact: str, support: str) -> bool:
    kind, value = fact.split(":", 1)
    if kind == "score":
        variants = {value, value.removesuffix(".0")}
        return any(re.search(rf"(?<![\d.]){re.escape(v)}(?![\d])", support) for v in variants)
    return contains(support, value)


# --- Notation d'un résultat ------------------------------------------------------------------------------------


def score_result(result: dict[str, Any]) -> dict[str, Any]:
    """Calcule les métriques d'une réponse à partir des champs bruts enregistrés."""
    answer, question = result["answer"], result["question"]
    expected = result.get("expected_contains", [])
    context = "\n".join(s["text"] for s in result.get("sources", []))
    reference = result.get("reference_text", "")
    uses_context = result["system"] != "llm_only"

    matched = [item for item in expected if contains(answer, item)]
    absent_from_question = [item for item in expected if not contains(question, item)]
    metrics: dict[str, Any] = {
        "coverage": len(matched) / len(expected) if expected else None,
        "matched": matched,
        "expected_not_in_question": len(absent_from_question),
        "found_not_in_question": sum(1 for item in absent_from_question if item in matched),
    }

    facts = answer_facts(answer)
    unsupported_by_sources = [f for f in facts if not fact_supported(f, f"{question}\n{context}")]
    invented = [f for f in unsupported_by_sources if not fact_supported(f, reference)]
    complete = metrics["found_not_in_question"] == metrics["expected_not_in_question"]
    abstention = not complete and is_abstention(answer)
    metrics.update(
        {
            "facts": facts,
            "invented_facts": invented,
            "invented": bool(invented),
            "complete": complete,
            "abstention": abstention,
            # Réponse fausse ou incomplète affirmée sans réserve, ou fait vérifiable inventé
            "hallucination": (not complete and not abstention) or bool(invented),
        }
    )

    if uses_context:
        sources = result.get("sources", [])
        refs = set(result.get("reference_doc_ids", []))
        metrics.update(
            {
                "faithfulness": (1 - len(unsupported_by_sources) / len(facts)) if facts else None,
                "unsupported_facts": unsupported_by_sources,
                "context_recall": (sum(contains(context, item) for item in expected) / len(expected))
                if expected
                else None,
                "context_precision": (sum(s["doc_id"] in refs for s in sources) / len(sources))
                if sources and refs
                else None,
            }
        )
    return metrics


def _mean(values: list[float | None]) -> float | None:
    values = [v for v in values if v is not None]
    return round(statistics.mean(values), 3) if values else None


def _rate(scored: list[dict[str, Any]], key: str) -> float | None:
    return round(sum(bool(r["metrics"][key]) for r in scored) / len(scored), 3) if scored else None


def summarize(results: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    scored = [r | {"metrics": score_result(r)} for r in results]
    by_category: dict[str, list[dict[str, Any]]] = {}
    for r in scored:
        by_category.setdefault(r["category"], []).append(r)
    expected_absent = sum(r["metrics"]["expected_not_in_question"] for r in scored)
    found_absent = sum(r["metrics"]["found_not_in_question"] for r in scored)
    return {
        "questions": len(scored),
        "coverage": _mean([r["metrics"]["coverage"] for r in scored]),
        "coverage_by_category": {
            c: _mean([r["metrics"]["coverage"] for r in rs]) for c, rs in sorted(by_category.items())
        },
        "found_not_in_question": f"{found_absent}/{expected_absent}",
        "context_recall": _mean([r["metrics"].get("context_recall") for r in scored]),
        "context_precision": _mean([r["metrics"].get("context_precision") for r in scored]),
        "faithfulness": _mean([r["metrics"].get("faithfulness") for r in scored]),
        "hallucination_rate": _rate(scored, "hallucination"),
        "abstention_rate": _rate(scored, "abstention"),
        "invented_facts_rate": _rate(scored, "invented"),
        "retrieval_modes": dict(Counter(r.get("retrieval_mode") for r in scored)),
        "latency_s": _mean([r.get("latency_s") for r in scored]),
    }, scored


# --- Exécution -------------------------------------------------------------------------------------------------


def load_questions(path: Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def reference_text(pipeline: Any, reference_ids: list[str]) -> tuple[list[str], str]:
    doc_ids = [pipeline.retriever.doc_for_id[i] for i in reference_ids if i in pipeline.retriever.doc_for_id]
    texts = [pipeline.store.chunks[p]["text"] for d in doc_ids for p in pipeline.store.by_doc[d]]
    return doc_ids, "\n".join(texts)


def run_mode(
    pipeline: Any, questions: list[dict[str, Any]], system: str, progress: Callable[[str], None] | None = None
) -> list[dict[str, Any]]:
    results = []
    for n, q in enumerate(questions, start=1):
        if progress:
            progress(f"[{system}] {n}/{len(questions)} {q['id']} – {q['question']}")
        if system == "llm_only":
            answer = pipeline.answer_without_context(q["question"])
        else:
            answer = pipeline.answer(q["question"], mode=system)
        ref_doc_ids, ref_text = reference_text(pipeline, q.get("reference_ids", []))
        results.append(
            {
                "id": q["id"],
                "category": q["category"],
                "question": q["question"],
                "expected_contains": q["expected_contains"],
                "reference_ids": q.get("reference_ids", []),
                "reference_doc_ids": ref_doc_ids,
                "reference_text": ref_text,
                "system": system,
                "retrieval_mode": answer.mode,
                "answer": answer.answer,
                "latency_s": round(answer.latency_s, 2),
                "sources": [
                    {"chunk_id": c.chunk_id, "doc_id": c.doc_id, "score": round(c.score, 4), "text": c.chunk["text"]}
                    for c in answer.retrieval.chunks
                ],
            }
        )
    return results


def write_results(results: list[dict[str, Any]], results_dir: Path, system: str, settings_info: dict[str, Any]) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    path = results_dir / f"{system}.json"
    payload = {
        "system": system,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "settings": settings_info,
        "results": results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


def load_results(results_dir: Path) -> dict[str, dict[str, Any]]:
    loaded = {}
    for system in EVAL_MODES:
        path = results_dir / f"{system}.json"
        if path.exists():
            with open(path, encoding="utf-8") as f:
                loaded[system] = json.load(f)
    return loaded


# --- Rapport ---------------------------------------------------------------------------------------------------

_LABELS = {"hybrid": "RAG hybride", "faiss": "RAG FAISS", "llm_only": "LLM seul"}


def _fmt(value: Any) -> str:
    if value is None:
        return "–"
    if isinstance(value, float):
        return f"{value:.3f}".replace(".", ",")
    return str(value)


def build_report(results_dir: Path) -> tuple[dict[str, Any], str]:
    """Agrège les fichiers de résultats, écrit summary.json et rapport_evaluation.md, renvoie le résumé."""
    loaded = load_results(results_dir)
    if not loaded:
        raise FileNotFoundError(f"Aucun résultat dans {results_dir}. Lancez d'abord : python -m rag_cyber evaluate")

    summaries, scored = {}, {}
    for system, payload in loaded.items():
        summaries[system], scored[system] = summarize(payload["results"])
    systems = list(summaries)
    settings_info = next(iter(loaded.values())).get("settings", {})

    rows = [
        ("Couverture des éléments attendus", "coverage"),
        ("Éléments absents de la question retrouvés", "found_not_in_question"),
        ("Rappel du contexte", "context_recall"),
        ("Précision du contexte", "context_precision"),
        ("Fidélité au contexte", "faithfulness"),
        ("Taux d'hallucination : réponse fausse ou incomplète, sans réserve", "hallucination_rate"),
        ("Abstentions : réponse incomplète signalée", "abstention_rate"),
        ("Réponses citant un fait vérifiable inventé", "invented_facts_rate"),
        ("Latence moyenne (s)", "latency_s"),
    ]
    lines = [
        "# Rapport d'évaluation",
        "",
        f"Généré le {datetime.now(UTC):%Y-%m-%d %H:%M} UTC à partir de `{results_dir.as_posix()}`.",
        "",
        "| Réglage | Valeur |",
        "|---|---|",
        *[f"| {k} | `{v}` |" for k, v in settings_info.items()],
        "",
        "## Résultats globaux",
        "",
        "| Métrique | " + " | ".join(_LABELS[s] for s in systems) + " |",
        "|---|" + "---|" * len(systems),
        *[f"| {label} | " + " | ".join(_fmt(summaries[s][key]) for s in systems) + " |" for label, key in rows],
        "",
        "## Couverture par catégorie",
        "",
        "| Catégorie | " + " | ".join(_LABELS[s] for s in systems) + " |",
        "|---|" + "---|" * len(systems),
    ]
    categories = sorted({c for s in systems for c in summaries[s]["coverage_by_category"]})
    lines += [
        f"| {c} | " + " | ".join(_fmt(summaries[s]["coverage_by_category"].get(c)) for s in systems) + " |"
        for c in categories
    ]
    lines += [
        "",
        "## Détail par question",
        "",
        "Couverture et mode de recherche ; ⚠ : réponse fausse ou incomplète donnée sans réserve (avec les faits inventés "
        "éventuels) ; ∅ : abstention.",
        "",
        "| Question | " + " | ".join(_LABELS[s] for s in systems) + " |",
        "|---|" + "---|" * len(systems),
    ]
    by_id = {s: {r["id"]: r for r in scored[s]} for s in systems}
    question_ids = list(dict.fromkeys(r["id"] for s in systems for r in scored[s]))
    for qid in question_ids:
        cells = []
        for s in systems:
            r = by_id[s].get(qid)
            if r is None:
                cells.append("–")
                continue
            m = r["metrics"]
            flag = ""
            if m["hallucination"]:
                flag = " ⚠" + "".join(f" {f.split(':', 1)[1]}" for f in m["invented_facts"])
            elif m["abstention"]:
                flag = " ∅"
            cells.append(f"{_fmt(m['coverage'])} ({r['retrieval_mode']}){flag}")
        question = next(by_id[s][qid]["question"] for s in systems if qid in by_id[s])
        lines.append(f"| {qid} : {question} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "## Définitions",
        "",
        "- **Couverture** : part des éléments attendus (ID, nom officiel, produit, sévérité, CWE) présents dans la réponse, "
        "en mot entier et sans tenir compte de la casse ; une sévérité attendue en anglais est aussi acceptée en français.",
        "- **Rappel du contexte** : part des éléments attendus présents dans les extraits transmis au LLM.",
        "- **Précision du contexte** : part des extraits transmis qui proviennent du ou des documents de référence de la question.",
        "- **Fidélité** : part des faits vérifiables de la réponse (identifiants CVE, ATT&CK, CWE, DET, M ; scores CVSS ; "
        "sévérités) présents dans la question ou les extraits transmis. Moyenne sur les réponses qui citent au moins un fait.",
        "- **Taux d'hallucination** : part des réponses qui manquent un élément attendu absent de la question sans le "
        "signaler, ou qui citent un fait vérifiable inventé. Une réponse qui donne un mauvais nom de technique compte ici.",
        "- **Abstentions** : part des réponses incomplètes qui disent ne pas pouvoir répondre.",
        "- **Faits inventés** : part des réponses citant un fait vérifiable absent de la question, des extraits transmis "
        "et des documents de référence de la base.",
        "",
        "Ces métriques sont des approximations par entités de celles de RAGAS : elles ne jugent pas les paraphrases.",
    ]
    report = "\n".join(lines) + "\n"
    with open(results_dir / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summaries, f, ensure_ascii=False, indent=2)
    with open(results_dir / "rapport_evaluation.md", "w", encoding="utf-8") as f:
        f.write(report)
    return summaries, report
