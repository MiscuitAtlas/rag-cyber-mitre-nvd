"""Chatbot Streamlit : streamlit run app.py"""

from __future__ import annotations

from typing import Any

import streamlit as st

from rag_cyber.config import get_settings
from rag_cyber.index import IndexNotFoundError
from rag_cyber.llm import LLMError
from rag_cyber.pipeline import RagPipeline
from rag_cyber.retrieval import Retrieval

st.set_page_config(page_title="RAG cyber : ATT&CK, CVE, CWE", page_icon="🛡️")

SEARCH_MODES = {"hybrid": "Hybride : FAISS + BM25", "faiss": "Vectorielle : FAISS seul"}
RETRIEVAL_LABELS = {
    "exact": "correspondance exacte sur l'identifiant",
    "hybrid": "recherche hybride FAISS + BM25",
    "faiss": "recherche vectorielle FAISS",
    "id_not_found": "identifiant absent de la base",
}
EXAMPLES = [
    "What is T1053.005 and how can it be detected?",
    "Quelle est la sévérité et la faiblesse de CVE-2025-14037 ?",
    "Quelles techniques ATT&CK utilisent les tâches planifiées ?",
]


@st.cache_resource(show_spinner="Chargement de l'index et du modèle d'embeddings…")
def load_pipeline() -> RagPipeline:
    return RagPipeline.from_settings(get_settings())


def serialize(retrieval: Retrieval) -> dict[str, Any]:
    return {
        "mode": retrieval.mode,
        "missing_ids": retrieval.missing_ids,
        "sources": [
            {
                "chunk_id": item.chunk_id,
                "score": item.score,
                "vector": item.vector_score,
                "bm25": item.bm25_score,
                "match": item.match,
                "text": item.chunk["text"],
            }
            for item in retrieval.chunks
        ],
    }


def render_missing(info: dict[str, Any]) -> None:
    if info["missing_ids"] and info["sources"]:
        st.warning("Absent(s) de la base : " + ", ".join(info["missing_ids"]))


def render_sources(info: dict[str, Any]) -> None:
    label = RETRIEVAL_LABELS.get(info["mode"], info["mode"])
    if not info["sources"]:
        st.caption(f"Recherche : {label}")
        return
    with st.expander(f"{len(info['sources'])} sources · {label}"):
        for i, source in enumerate(info["sources"], start=1):
            if source["match"] == "hybrid":
                score = f"score {source['score']:.3f} (vecteur {source['vector']:.3f}, BM25 {source['bm25']:.3f})"
            elif source["match"] == "vector":
                score = f"similarité {source['score']:.3f}"
            else:
                score = "identifiant cité dans la question"
            st.markdown(f"**[S{i}]** `{source['chunk_id']}` · {score}")
            st.text(source["text"])  # texte brut : une description de CVE ne doit pas être interprétée en Markdown


try:
    pipeline = load_pipeline()
except IndexNotFoundError:
    st.error("L'index FAISS n'existe pas encore. Construisez-le depuis la racine du dépôt :")
    st.code("python -m rag_cyber prepare --sample\npython -m rag_cyber index", language="bash")
    st.stop()

settings = pipeline.settings
manifest = pipeline.store.manifest

with st.sidebar:
    st.header("Réglages")
    mode = st.radio("Recherche sans identifiant", list(SEARCH_MODES), format_func=SEARCH_MODES.get)
    top_k = st.slider("Extraits transmis au LLM", min_value=1, max_value=10, value=settings.top_k)
    st.caption(
        "Une question qui cite une CVE ou une technique (T1053.005) passe par la correspondance exacte, quel que soit le mode."
    )
    if st.button("Effacer la conversation", width="stretch"):
        st.session_state.messages = []
    st.divider()
    st.caption(
        f"Base : {manifest.get('documents', '?')} documents, {len(pipeline.store.chunks)} chunks, "
        f"index du {str(manifest.get('created_at', '?'))[:10]}  \n"
        f"Embeddings : {pipeline.store.embed_model}  \nLLM : {settings.ollama_model} via Ollama (local)"
    )

st.title("Assistant RAG cybersécurité")
st.caption("MITRE ATT&CK, CVE du NVD et CWE. Réponses générées en local à partir des extraits cités.")

if "messages" not in st.session_state:
    st.session_state.messages = []


for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        if message.get("retrieval"):
            render_missing(message["retrieval"])
        st.markdown(message["content"])
        if message.get("retrieval"):
            render_sources(message["retrieval"])

question = st.chat_input("Posez une question sur une technique ATT&CK, une CVE ou une CWE…")
question = question or st.session_state.pop("pending", None)

if not st.session_state.messages and not question:
    st.write("Exemples :")
    for example in EXAMPLES:
        if st.button(example):
            st.session_state.pending = example
            st.rerun()

if question:
    st.session_state.messages.append({"role": "user", "content": question})
    with st.chat_message("user"):
        st.markdown(question)
    with st.chat_message("assistant"):
        retrieval, pieces = pipeline.stream(question, mode=mode, top_k=top_k)
        info = serialize(retrieval)
        render_missing(info)
        try:
            answer = st.write_stream(pieces)
        except LLMError as exc:
            st.error(str(exc))
            answer = f"⚠️ {exc}"
        render_sources(info)
    st.session_state.messages.append({"role": "assistant", "content": answer, "retrieval": info})
