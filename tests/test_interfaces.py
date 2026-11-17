"""Ligne de commande et interface Streamlit, avec l'embedder et le LLM factices."""

import json

import pytest
from conftest import ROOT, FakeLLM, HashEmbedder

import rag_cyber.index
import rag_cyber.pipeline
from rag_cyber.cli import main


@pytest.fixture()
def built_index(tmp_path, monkeypatch):
    """prepare --sample puis index, dans un dossier temporaire, sans télécharger de modèle."""
    monkeypatch.setattr(rag_cyber.index, "SentenceTransformerEmbedder", lambda name: HashEmbedder())
    monkeypatch.setattr(rag_cyber.pipeline, "SentenceTransformerEmbedder", lambda name: HashEmbedder())
    data_dir, index_dir = tmp_path / "processed", tmp_path / "index"
    assert main(["--data-dir", str(data_dir), "prepare", "--sample"]) == 0
    assert main(["--data-dir", str(data_dir), "--index-dir", str(index_dir), "index"]) == 0
    monkeypatch.setenv("RAG_DATA_DIR", str(data_dir))
    monkeypatch.setenv("RAG_INDEX_DIR", str(index_dir))
    return data_dir, index_dir


def test_prepare_and_index_from_sample(built_index):
    data_dir, index_dir = built_index
    documents = json.loads((data_dir / "rag_documents.json").read_text(encoding="utf-8"))
    manifest = json.loads((index_dir / "manifest.json").read_text(encoding="utf-8"))
    assert len(documents) == 100
    assert manifest["documents"] == 100 and manifest["chunk_size"] == 120


def test_prepare_without_downloads_explains_next_step(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("RAG_RAW_DIR", str(tmp_path / "raw"))
    assert main(["--data-dir", str(tmp_path), "prepare"]) == 1
    assert "python -m rag_cyber download" in capsys.readouterr().err


def test_ask_prints_answer_and_sources(built_index, monkeypatch, capsys):
    fake = FakeLLM("T1053.005 est la sous-technique Scheduled Task [S1]")
    monkeypatch.setattr(rag_cyber.pipeline, "OllamaClient", lambda *args, **kwargs: fake)
    assert main(["ask", "What is T1053.005?"]) == 0
    out = capsys.readouterr().out
    assert "Scheduled Task" in out and "Recherche : exact" in out and "[S1] mitre:T1053.005#0" in out


def test_report_without_results(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("RAG_EVAL_DIR", str(tmp_path))
    assert main(["report"]) == 1
    assert "python -m rag_cyber evaluate" in capsys.readouterr().err


# --- Streamlit ------------------------------------------------------------------------------------------------

streamlit_testing = pytest.importorskip("streamlit.testing.v1")


@pytest.fixture()
def app_test():
    import streamlit as st

    st.cache_resource.clear()
    return streamlit_testing.AppTest.from_file(str(ROOT / "app.py"), default_timeout=30)


def test_app_without_index_shows_build_commands(app_test, tmp_path, monkeypatch):
    monkeypatch.setenv("RAG_INDEX_DIR", str(tmp_path / "missing"))
    app_test.run()
    assert "n'existe pas encore" in app_test.error[0].value
    assert "python -m rag_cyber index" in app_test.code[0].value


def test_app_chat_round_trip(app_test, built_index, monkeypatch):
    fake = FakeLLM("CVE-2025-14037 : sévérité HIGH, CWE-352 [S1]")
    monkeypatch.setattr(rag_cyber.pipeline, "OllamaClient", lambda *args, **kwargs: fake)
    app_test.run()
    assert not app_test.exception
    app_test.chat_input[0].set_value("What is the severity of CVE-2025-14037?").run()
    assert not app_test.exception
    assistant = app_test.chat_message[-1]
    assert "CWE-352" in assistant.markdown[0].value
    assert "correspondance exacte" in assistant.expander[0].label


def test_app_shows_ollama_errors(app_test, built_index, monkeypatch):
    from rag_cyber.llm import LLMError

    class DownLLM(FakeLLM):
        def stream_chat(self, messages):
            raise LLMError("Impossible de joindre Ollama")
            yield  # pragma: no cover

    monkeypatch.setattr(rag_cyber.pipeline, "OllamaClient", lambda *args, **kwargs: DownLLM())
    app_test.run()
    app_test.chat_input[0].set_value("What is T1053.005?").run()
    assert "Impossible de joindre Ollama" in app_test.error[0].value


def test_app_unknown_id_needs_no_llm(app_test, built_index, monkeypatch):
    fake = FakeLLM()
    monkeypatch.setattr(rag_cyber.pipeline, "OllamaClient", lambda *args, **kwargs: fake)
    app_test.run()
    app_test.chat_input[0].set_value("What is CVE-2021-44228?").run()
    assert "Aucun document" in app_test.chat_message[-1].markdown[0].value
    assert fake.calls == []


def test_app_keeps_missing_id_warning_in_history(app_test, built_index, monkeypatch):
    monkeypatch.setattr(rag_cyber.pipeline, "OllamaClient", lambda *args, **kwargs: FakeLLM())
    app_test.run()
    app_test.chat_input[0].set_value("CVE-2025-14037 et CVE-2021-44228 : quelle sévérité ?").run()
    assert "CVE-2021-44228" in app_test.chat_message[-1].warning[0].value
    app_test.run()  # nouvel affichage : la conversation est relue depuis l'historique
    assert "CVE-2021-44228" in app_test.chat_message[-1].warning[0].value
