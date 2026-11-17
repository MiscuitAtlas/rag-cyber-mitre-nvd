import numpy as np
import pytest

from rag_cyber.index import IndexNotFoundError, load_store, save_store
from rag_cyber.retrieval import tokenize


def test_tokenize_keeps_identifiers_whole_and_split():
    tokens = tokenize("CVE-2025-14037 and T1053.005")
    assert "cve-2025-14037" in tokens and "14037" in tokens
    assert "t1053.005" in tokens and "t1053" in tokens


def test_exact_match_returns_overview_first(retriever):
    result = retriever.retrieve("Which detection strategy covers T1053.005?")
    assert result.mode == "exact"
    assert {c.doc_id for c in result.chunks} == {"mitre:T1053.005"}
    assert result.chunks[0].chunk["section"] == "Overview"
    assert len(result.chunks) == 5
    # la détection est la section la plus proche de la question parmi les autres chunks
    assert "Detection" in {c.chunk["section"] for c in result.chunks}


def test_exact_match_handles_several_ids(retriever):
    result = retriever.retrieve("Compare T1053.005 with T1053.003 and CVE-2025-14037", top_k=2)
    assert result.mode == "exact"
    assert [c.chunk["section"] for c in result.chunks] == ["Overview"] * 3
    assert [c.doc_id for c in result.chunks] == ["mitre:T1053.005", "mitre:T1053.003", "cve:CVE-2025-14037"]


def test_unknown_id_does_not_fall_back_to_semantic_search(retriever):
    result = retriever.retrieve("What is CVE-2021-44228?")
    assert result.mode == "id_not_found"
    assert result.chunks == []
    assert result.missing_ids == ["CVE-2021-44228"]


def test_partially_unknown_ids_are_reported(retriever):
    result = retriever.retrieve("T1053.005 vs T1999")
    assert result.mode == "exact"
    assert result.missing_ids == ["T1999"]
    assert {c.doc_id for c in result.chunks} == {"mitre:T1053.005"}


def test_short_document_is_returned_whole_in_reading_order(retriever):
    result = retriever.retrieve("What is CVE-2025-14037?")
    assert [c.chunk_id for c in result.chunks] == ["cve:CVE-2025-14037#0", "cve:CVE-2025-14037#1"]


def test_hybrid_scores_combine_vector_and_bm25(retriever):
    result = retriever.retrieve("scheduled task persistence windows", mode="hybrid")
    assert result.mode == "hybrid"
    assert len(result.chunks) == 5
    for item in result.chunks:
        assert item.score == pytest.approx(0.6 * item.vector_score + 0.4 * item.bm25_score)
    assert [c.score for c in result.chunks] == sorted((c.score for c in result.chunks), reverse=True)


def test_hybrid_finds_cwe_mentions_through_bm25(retriever):
    result = retriever.retrieve("vulnerabilities with weakness CWE-352", mode="hybrid")
    top = result.chunks[0].chunk["text"]
    assert "CWE-352" in top


def test_faiss_mode_returns_cosine_similarities(retriever):
    result = retriever.retrieve("scheduled task", mode="faiss", top_k=3)
    assert result.mode == "faiss"
    assert len(result.chunks) == 3
    assert all(-1.0 <= c.score <= 1.0 for c in result.chunks)


def test_unknown_mode_is_rejected(retriever):
    with pytest.raises(ValueError):
        retriever.retrieve("anything", mode="bm25")


def test_store_round_trip(tmp_path, store, embedder):
    files = (tmp_path / "full.index", tmp_path / "full_chunks.json", tmp_path / "manifest.json")
    manifest = save_store(store.index, store.chunks, *files, embed_model=embedder.name)
    assert manifest["chunks"] == len(store.chunks) and manifest["documents"] == 100
    loaded = load_store(*files)
    assert loaded.embed_model == embedder.name
    query = embedder.encode(["scheduled task"])[0]
    assert loaded.search(query, 3) == store.search(query, 3)
    assert np.allclose(loaded.vectors, store.vectors)


def test_missing_index_has_actionable_error(tmp_path):
    with pytest.raises(IndexNotFoundError, match="python -m rag_cyber index"):
        load_store(tmp_path / "full.index", tmp_path / "full_chunks.json", tmp_path / "manifest.json")
