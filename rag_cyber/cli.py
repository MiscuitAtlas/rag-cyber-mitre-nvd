"""Ligne de commande : python -m rag_cyber <commande>.

download   télécharge ATT&CK, le flux NVD récent et (option --cwe) le catalogue CWE
prepare    extrait techniques et CVE, construit documents et chunks (--sample : échantillon fourni)
index      calcule les embeddings et enregistre l'index FAISS
ask        pose une question au RAG
evaluate   compare RAG hybride, RAG FAISS et LLM seul sur data/eval/questions.json
report     régénère le rapport d'évaluation à partir des résultats enregistrés
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from rag_cyber.config import Settings, get_settings

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "data" / "sample"


def _read_json(path: Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def cmd_download(args: argparse.Namespace, settings: Settings) -> int:
    from rag_cyber import download

    steps = [
        ("MITRE ATT&CK", download.download_mitre, settings.mitre_raw),
        ("NVD (flux recent)", download.download_nvd_recent, settings.nvd_raw),
    ]
    if args.cwe:
        steps.append(("Catalogue CWE", download.download_cwe, settings.cwe_raw))
    for label, func, target in steps:
        print(f"Téléchargement {label}…")
        func(target)
        print(f"  → {target} ({target.stat().st_size / 1e6:.1f} Mo)")
    return 0


def cmd_prepare(args: argparse.Namespace, settings: Settings) -> int:
    from rag_cyber.documents import build_documents, chunk_documents

    cwe_names: dict[str, str] = {}
    if args.sample:
        print(f"Échantillon : {SAMPLE_DIR}")
        techniques = _read_json(SAMPLE_DIR / "mitre_techniques.json")
        cves = _read_json(SAMPLE_DIR / "nvd_recent_cves.json")
        if (SAMPLE_DIR / "cwe_names.json").exists():
            cwe_names = _read_json(SAMPLE_DIR / "cwe_names.json")
    else:
        from rag_cyber.cwe import parse_cwe_catalog
        from rag_cyber.mitre import extract_techniques, load_bundle
        from rag_cyber.nvd import extract_cves, load_feed

        missing = [p for p in (settings.mitre_raw, settings.nvd_raw) if not p.exists()]
        if missing:
            raise FileNotFoundError(
                "Fichiers sources absents : "
                + ", ".join(map(str, missing))
                + ".\nLancez d'abord : python -m rag_cyber download  (ou prepare --sample pour l'échantillon)"
            )
        techniques = extract_techniques(load_bundle(settings.mitre_raw))
        cves = extract_cves(load_feed(settings.nvd_raw))
        if settings.cwe_raw.exists():
            cwe_names = parse_cwe_catalog(settings.cwe_raw)
        else:
            print("Catalogue CWE absent : les CWE seront cités sans leur nom (python -m rag_cyber download --cwe).")

    _write_json(settings.techniques_file, techniques)
    _write_json(settings.cves_file, cves)
    if cwe_names:
        _write_json(settings.cwe_file, cwe_names)
    documents = build_documents(techniques, cves, cwe_names)
    chunks = chunk_documents(documents, settings.chunk_size, settings.chunk_overlap)
    _write_json(settings.documents_file, documents)
    _write_json(settings.chunks_file, chunks)
    print(f"{len(techniques)} techniques ATT&CK, {len(cves)} CVE, {len(cwe_names)} noms de CWE")
    print(f"{len(documents)} documents → {len(chunks)} chunks dans {settings.data_dir}")
    return 0


def cmd_index(args: argparse.Namespace, settings: Settings) -> int:
    from rag_cyber.index import SentenceTransformerEmbedder, build_index, save_store

    if not settings.chunks_file.exists():
        raise FileNotFoundError(f"{settings.chunks_file} absent. Lancez d'abord : python -m rag_cyber prepare")
    chunks = _read_json(settings.chunks_file)
    print(f"Embeddings de {len(chunks)} chunks avec {settings.embed_model}…")
    embedder = SentenceTransformerEmbedder(settings.embed_model)
    index = build_index(chunks, embedder, show_progress=True)
    manifest = save_store(
        index,
        chunks,
        settings.index_file,
        settings.index_chunks_file,
        settings.manifest_file,
        settings.embed_model,
        {"chunk_size": settings.chunk_size, "chunk_overlap": settings.chunk_overlap},
    )
    print(f"Index FAISS : {manifest['chunks']} vecteurs de dimension {manifest['dimension']} → {settings.index_dir}")
    return 0


def _print_sources(retrieval: Any) -> None:
    print(
        f"\n--- Recherche : {retrieval.mode}"
        + (f" (absents de la base : {', '.join(retrieval.missing_ids)})" if retrieval.missing_ids else "")
    )
    for i, item in enumerate(retrieval.chunks, start=1):
        detail = f"score {item.score:.3f}"
        if item.match == "hybrid":
            detail += f" = vecteur {item.vector_score:.3f} / BM25 {item.bm25_score:.3f}"
        first_line = item.chunk["text"].split("\n", 1)[0]
        print(f"[S{i}] {item.chunk_id} ({detail}) {first_line}")


def cmd_ask(args: argparse.Namespace, settings: Settings) -> int:
    from rag_cyber.pipeline import RagPipeline

    pipeline = RagPipeline.from_settings(settings)
    retrieval, pieces = pipeline.stream(args.question, mode=args.mode, top_k=args.top_k)
    for piece in pieces:
        print(piece, end="", flush=True)
    print()
    _print_sources(retrieval)
    return 0


def cmd_evaluate(args: argparse.Namespace, settings: Settings) -> int:
    from rag_cyber.evaluation import load_questions, run_mode, write_results
    from rag_cyber.pipeline import RagPipeline

    pipeline = RagPipeline.from_settings(settings)
    questions = load_questions(settings.questions_file)[: args.limit or None]
    info = {
        "ollama_model": settings.ollama_model,
        "embed_model": pipeline.store.embed_model,
        "top_k": settings.top_k,
        "hybrid_alpha": settings.hybrid_alpha,
        "temperature": settings.temperature,
        "seed": settings.seed,
        "corpus": f"{pipeline.store.manifest.get('documents', '?')} documents, {len(pipeline.store.chunks)} chunks",
        "index_created_at": pipeline.store.manifest.get("created_at", "?"),
    }
    for system in args.modes:
        results = run_mode(pipeline, questions, system, progress=print)
        print(f"  → {write_results(results, settings.results_dir, system, info)}")
    return _report(settings)


def _report(settings: Settings) -> int:
    from rag_cyber.evaluation import build_report

    summaries, _ = build_report(settings.results_dir)
    for system, summary in summaries.items():
        print(
            f"{system:9} couverture {summary['coverage']}  rappel ctx {summary['context_recall']}  "
            f"précision ctx {summary['context_precision']}  fidélité {summary['faithfulness']}  "
            f"hallucinations {summary['hallucination_rate']}"
        )
    print(f"Rapport : {settings.results_dir / 'rapport_evaluation.md'}")
    return 0


def cmd_report(args: argparse.Namespace, settings: Settings) -> int:
    return _report(settings)


def build_parser() -> argparse.ArgumentParser:
    from rag_cyber.evaluation import EVAL_MODES
    from rag_cyber.retrieval import MODES

    parser = argparse.ArgumentParser(prog="python -m rag_cyber", description="Assistant RAG MITRE ATT&CK / NVD / CWE")
    parser.add_argument("--data-dir", type=Path, help="dossier des données préparées (défaut : data/processed)")
    parser.add_argument("--index-dir", type=Path, help="dossier de l'index FAISS (défaut : vectorstore/faiss_index)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("download", help="télécharger les sources")
    p.add_argument("--cwe", action="store_true", help="télécharger aussi le catalogue CWE")
    p.set_defaults(func=cmd_download)

    p = sub.add_parser("prepare", help="extraire les données et construire documents et chunks")
    p.add_argument("--sample", action="store_true", help="utiliser l'échantillon de data/sample")
    p.set_defaults(func=cmd_prepare)

    sub.add_parser("index", help="construire l'index FAISS").set_defaults(func=cmd_index)

    p = sub.add_parser("ask", help="poser une question")
    p.add_argument("question")
    p.add_argument("--mode", choices=MODES, default="hybrid")
    p.add_argument("--top-k", type=int)
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("evaluate", help="évaluer RAG et LLM seul")
    p.add_argument("--modes", nargs="+", choices=EVAL_MODES, default=list(EVAL_MODES))
    p.add_argument("--limit", type=int, help="n'évaluer que les N premières questions")
    p.set_defaults(func=cmd_evaluate)

    sub.add_parser("report", help="régénérer le rapport d'évaluation").set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    import requests

    from rag_cyber.index import IndexNotFoundError
    from rag_cyber.llm import LLMError

    # Sortie redirigée sous Windows (cp1252) : un caractère non représentable ne doit pas interrompre la commande.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    settings = get_settings(data_dir=args.data_dir, index_dir=args.index_dir)
    try:
        return args.func(args, settings)
    except (IndexNotFoundError, FileNotFoundError, LLMError) as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1
    except requests.RequestException as exc:
        print(f"Erreur réseau : {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
