"""Outils de test : embedder déterministe (sans PyTorch ni téléchargement) et LLM factice."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pytest

from rag_cyber.config import get_settings
from rag_cyber.documents import build_documents, chunk_documents
from rag_cyber.index import VectorStore, build_index
from rag_cyber.pipeline import RagPipeline
from rag_cyber.retrieval import Retriever, tokenize

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SAMPLE = ROOT / "data" / "sample"


class HashEmbedder:
    """Sac de mots haché sur 256 dimensions puis normalisé : assez pour tester le classement, sans modèle."""

    name = "test-hash-embedder"

    def __init__(self, dim: int = 256):
        self.dim = dim

    def encode(self, texts: list[str], show_progress: bool = False) -> np.ndarray:
        vectors = np.zeros((len(texts), self.dim), dtype="float32")
        for row, text in enumerate(texts):
            for token in tokenize(text):
                bucket = int(hashlib.md5(token.encode(), usedforsecurity=False).hexdigest(), 16) % self.dim
                vectors[row, bucket] += 1.0
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        return vectors / np.where(norms == 0, 1, norms)


class FakeLLM:
    def __init__(self, reply: str = "Réponse de test [S1]"):
        self.reply = reply
        self.calls: list[list[dict[str, str]]] = []

    def chat(self, messages):
        self.calls.append(messages)
        return self.reply

    def stream_chat(self, messages):
        self.calls.append(messages)
        yield from self.reply.split(" ")


def load_json(path: Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def sample_chunks() -> list[dict]:
    documents = build_documents(load_json(SAMPLE / "mitre_techniques.json"), load_json(SAMPLE / "nvd_recent_cves.json"))
    return chunk_documents(documents, 120, 30)


@pytest.fixture(scope="session")
def embedder() -> HashEmbedder:
    return HashEmbedder()


@pytest.fixture(scope="session")
def store(sample_chunks, embedder) -> VectorStore:
    index = build_index(sample_chunks, embedder)
    return VectorStore(index=index, chunks=sample_chunks, manifest={"embed_model": embedder.name, "documents": 100})


@pytest.fixture()
def retriever(store, embedder) -> Retriever:
    return Retriever(store, embedder, top_k=5, candidates=10, alpha=0.6)


@pytest.fixture()
def fake_llm() -> FakeLLM:
    return FakeLLM()


@pytest.fixture()
def pipeline(store, embedder, fake_llm) -> RagPipeline:
    return RagPipeline(store, embedder, fake_llm, get_settings())
