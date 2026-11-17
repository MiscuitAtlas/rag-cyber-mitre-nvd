"""Recherche des chunks : correspondance exacte sur les identifiants, puis FAISS seul ou hybride FAISS + BM25."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from rank_bm25 import BM25Okapi

from rag_cyber.ids import find_lookup_ids
from rag_cyber.index import Embedder, VectorStore

MODES = ("hybrid", "faiss")

# Garde « cve-2024-13785 », « t1053.005 » ou « cwe-79 » en un seul jeton, en plus de leurs morceaux.
_TOKEN_RE = re.compile(r"[a-z0-9]+(?:[.\-_][a-z0-9]+)*")


def tokenize(text: str) -> list[str]:
    tokens = []
    for token in _TOKEN_RE.findall(text.lower()):
        tokens.append(token)
        parts = re.split(r"[.\-_]", token)
        if len(parts) > 1:
            tokens.extend(p for p in parts if p)
    return tokens


@dataclass
class RetrievedChunk:
    chunk: dict[str, Any]
    score: float
    match: str  # « exact », « vector » ou « hybrid »
    vector_score: float | None = None
    bm25_score: float | None = None

    @property
    def chunk_id(self) -> str:
        return self.chunk["chunk_id"]

    @property
    def doc_id(self) -> str:
        return self.chunk["doc_id"]


@dataclass
class Retrieval:
    mode: str  # « exact », « faiss », « hybrid » ou « id_not_found »
    chunks: list[RetrievedChunk] = field(default_factory=list)
    requested_ids: list[str] = field(default_factory=list)
    missing_ids: list[str] = field(default_factory=list)


class Retriever:
    def __init__(
        self, store: VectorStore, embedder: Embedder, top_k: int = 5, candidates: int = 10, alpha: float = 0.6
    ):
        if not 0.0 <= alpha <= 1.0:
            raise ValueError("alpha doit être compris entre 0 et 1.")
        self.store = store
        self.embedder = embedder
        self.top_k = top_k
        self.candidates = candidates
        self.alpha = alpha
        self._bm25: BM25Okapi | None = None
        self.doc_for_id: dict[str, str] = {}
        for chunk in store.chunks:
            meta = chunk.get("metadata", {})
            for key in ("attack_id", "cve_id"):
                if meta.get(key):
                    self.doc_for_id[str(meta[key]).upper()] = chunk["doc_id"]

    @property
    def bm25(self) -> BM25Okapi:
        if self._bm25 is None:
            self._bm25 = BM25Okapi([tokenize(chunk["text"]) for chunk in self.store.chunks])
        return self._bm25

    def _embed(self, text: str) -> np.ndarray:
        return np.asarray(self.embedder.encode([text]), dtype="float32")[0]

    def retrieve(self, query: str, mode: str = "hybrid", top_k: int | None = None) -> Retrieval:
        if mode not in MODES:
            raise ValueError(f"Mode inconnu : {mode}. Modes possibles : {', '.join(MODES)}.")
        top_k = top_k or self.top_k
        ids = find_lookup_ids(query)
        if ids:
            return self._exact(query, ids, top_k)
        if mode == "faiss":
            return Retrieval("faiss", self._vector(query, top_k))
        return Retrieval("hybrid", self._hybrid(query, top_k))

    def _exact(self, query: str, ids: list[str], top_k: int) -> Retrieval:
        found = [i for i in ids if i in self.doc_for_id]
        missing = [i for i in ids if i not in self.doc_for_id]
        if not found:
            # Aucun document : on ne se rabat pas sur la recherche sémantique, qui renverrait un autre identifiant.
            return Retrieval("id_not_found", [], ids, missing)

        doc_ids = list(dict.fromkeys(self.doc_for_id[i] for i in found))
        top_k = max(top_k, len(doc_ids))
        positions = [p for doc_id in doc_ids for p in self.store.by_doc[doc_id]]
        # La fiche (premier chunk) de chaque document d'abord : elle porte nom, type, sévérité, CWE...
        heads = [self.store.by_doc[doc_id][0] for doc_id in doc_ids]
        rest = [p for p in positions if p not in heads]
        if len(heads) + len(rest) <= top_k:
            return Retrieval(
                "exact", [RetrievedChunk(self.store.chunks[p], 1.0, "exact") for p in positions], ids, missing
            )

        query_vector = self._embed(query)
        scores = dict(zip(rest, self.store.similarities(query_vector, rest).tolist(), strict=True))
        ranked = sorted(rest, key=lambda p: scores[p], reverse=True)[: top_k - len(heads)]
        selected = heads + sorted(ranked, key=positions.index)  # ordre de lecture du document
        return Retrieval(
            "exact",
            [RetrievedChunk(self.store.chunks[p], 1.0, "exact", vector_score=scores.get(p)) for p in selected],
            ids,
            missing,
        )

    def _vector(self, query: str, top_k: int) -> list[RetrievedChunk]:
        hits = self.store.search(self._embed(query), top_k)
        return [RetrievedChunk(self.store.chunks[p], s, "vector", vector_score=s) for p, s in hits]

    def _hybrid(self, query: str, top_k: int) -> list[RetrievedChunk]:
        query_vector = self._embed(query)
        vector_hits = dict(self.store.search(query_vector, self.candidates))

        bm25_all = self.bm25.get_scores(tokenize(query))
        bm25_top = [int(p) for p in np.argsort(bm25_all)[::-1][: self.candidates] if bm25_all[p] > 0]
        bm25_max = float(bm25_all.max()) if len(bm25_all) else 0.0

        candidates = list(dict.fromkeys(list(vector_hits) + bm25_top))
        if not candidates:
            return []
        # Score vectoriel calculé pour tous les candidats, y compris ceux trouvés seulement par BM25.
        vector_scores = dict(zip(candidates, self.store.similarities(query_vector, candidates).tolist(), strict=True))
        ranked = []
        for p in candidates:
            v = max(0.0, vector_scores[p])
            b = float(bm25_all[p]) / bm25_max if bm25_max > 0 else 0.0
            ranked.append(RetrievedChunk(self.store.chunks[p], self.alpha * v + (1 - self.alpha) * b, "hybrid", v, b))
        ranked.sort(key=lambda r: r.score, reverse=True)
        return ranked[:top_k]
