"""Chaîne complète question → recherche → prompt → LLM, partagée par la CLI, l'interface et l'évaluation."""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass, field

from rag_cyber.config import Settings
from rag_cyber.index import Embedder, SentenceTransformerEmbedder, VectorStore, load_store
from rag_cyber.llm import OllamaClient
from rag_cyber.prompt import llm_only_messages, not_found_message, rag_messages
from rag_cyber.retrieval import Retrieval, Retriever


def _no_context_answer(retrieval: Retrieval) -> str:
    """Réponse sans appel au LLM quand la recherche ne renvoie rien : mieux vaut le dire que laisser le modèle inventer."""
    if retrieval.mode == "id_not_found":
        return not_found_message(retrieval.missing_ids)
    return "Aucun extrait pertinent n'a été trouvé dans la base : je ne peux pas répondre sans inventer."


@dataclass
class AnswerResult:
    question: str
    answer: str
    retrieval: Retrieval
    latency_s: float = 0.0
    messages: list[dict[str, str]] = field(default_factory=list)

    @property
    def mode(self) -> str:
        return self.retrieval.mode


class RagPipeline:
    def __init__(self, store: VectorStore, embedder: Embedder, llm: OllamaClient, settings: Settings):
        self.settings = settings
        self.store = store
        self.llm = llm
        self.retriever = Retriever(store, embedder, settings.top_k, settings.candidates, settings.hybrid_alpha)

    @classmethod
    def from_settings(cls, settings: Settings) -> RagPipeline:
        store = load_store(settings.index_file, settings.index_chunks_file, settings.manifest_file)
        # Les questions doivent être encodées avec le modèle qui a servi à construire l'index.
        embedder = SentenceTransformerEmbedder(store.embed_model or settings.embed_model)
        llm = OllamaClient(
            settings.ollama_url,
            settings.ollama_model,
            settings.temperature,
            settings.seed,
            settings.num_ctx,
            settings.timeout,
        )
        return cls(store, embedder, llm, settings)

    def retrieve(self, question: str, mode: str = "hybrid", top_k: int | None = None) -> Retrieval:
        return self.retriever.retrieve(question, mode=mode, top_k=top_k)

    def answer(self, question: str, mode: str = "hybrid", top_k: int | None = None) -> AnswerResult:
        start = time.perf_counter()
        retrieval = self.retrieve(question, mode, top_k)
        if not retrieval.chunks:
            return AnswerResult(question, _no_context_answer(retrieval), retrieval, time.perf_counter() - start)
        messages = rag_messages(question, retrieval)
        text = self.llm.chat(messages)
        return AnswerResult(question, text, retrieval, time.perf_counter() - start, messages)

    def stream(self, question: str, mode: str = "hybrid", top_k: int | None = None) -> tuple[Retrieval, Iterator[str]]:
        retrieval = self.retrieve(question, mode, top_k)
        if not retrieval.chunks:
            return retrieval, iter([_no_context_answer(retrieval)])
        return retrieval, self.llm.stream_chat(rag_messages(question, retrieval))

    def answer_without_context(self, question: str) -> AnswerResult:
        """Référence de l'évaluation : la même question posée au LLM seul."""
        start = time.perf_counter()
        messages = llm_only_messages(question)
        text = self.llm.chat(messages)
        return AnswerResult(question, text, Retrieval("llm_only"), time.perf_counter() - start, messages)
