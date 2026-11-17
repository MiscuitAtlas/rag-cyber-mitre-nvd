"""Embeddings et index FAISS persistant (index + chunks + manifeste)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import faiss
import numpy as np


class Embedder(Protocol):
    name: str

    def encode(self, texts: list[str], show_progress: bool = False) -> np.ndarray:
        """Vecteurs float32 normalisés (norme 1), un par texte."""
        ...


class SentenceTransformerEmbedder:
    """Modèle sentence-transformers chargé à la demande (le premier appel le télécharge depuis Hugging Face)."""

    def __init__(self, model_name: str, batch_size: int = 64):
        from sentence_transformers import SentenceTransformer  # import lourd (PyTorch), seulement si nécessaire

        self.name = model_name
        self.batch_size = batch_size
        self._model = SentenceTransformer(model_name)

    def encode(self, texts: list[str], show_progress: bool = False) -> np.ndarray:
        vectors = self._model.encode(
            texts,
            batch_size=self.batch_size,
            normalize_embeddings=True,
            show_progress_bar=show_progress,
        )
        return np.asarray(vectors, dtype="float32")


class IndexNotFoundError(FileNotFoundError):
    pass


@dataclass
class VectorStore:
    index: Any  # faiss.Index
    chunks: list[dict[str, Any]]
    manifest: dict[str, Any]

    def __post_init__(self) -> None:
        if self.index.ntotal != len(self.chunks):
            raise ValueError(
                f"Index incohérent : {self.index.ntotal} vecteurs pour {len(self.chunks)} chunks. Reconstruisez l'index."
            )
        # IndexFlatL2 conserve les vecteurs : on les garde pour noter n'importe quel chunk (BM25, correspondance exacte).
        self.vectors = (
            self.index.reconstruct_n(0, self.index.ntotal)
            if self.index.ntotal
            else np.zeros((0, self.index.d), "float32")
        )
        self.by_doc: dict[str, list[int]] = {}
        for position, chunk in enumerate(self.chunks):
            self.by_doc.setdefault(chunk["doc_id"], []).append(position)

    def search(self, query_vector: np.ndarray, k: int) -> list[tuple[int, float]]:
        """Plus proches voisins : (position, similarité cosinus). Pour des vecteurs unitaires, cos = 1 - d²/2."""
        k = min(k, self.index.ntotal)
        if k == 0:
            return []
        distances, positions = self.index.search(query_vector.reshape(1, -1).astype("float32"), k)
        return [(int(p), 1.0 - float(d) / 2.0) for d, p in zip(distances[0], positions[0], strict=True) if p >= 0]

    def similarities(self, query_vector: np.ndarray, positions: list[int]) -> np.ndarray:
        return self.vectors[positions] @ query_vector.reshape(-1)

    @property
    def embed_model(self) -> str:
        return self.manifest.get("embed_model", "")


def build_index(chunks: list[dict[str, Any]], embedder: Embedder, show_progress: bool = False) -> Any:
    vectors = np.asarray(
        embedder.encode([chunk["text"] for chunk in chunks], show_progress=show_progress), dtype="float32"
    )
    index = faiss.IndexFlatL2(vectors.shape[1])
    index.add(vectors)
    return index


def save_store(
    index: Any,
    chunks: list[dict[str, Any]],
    index_file: Path,
    chunks_file: Path,
    manifest_file: Path,
    embed_model: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    index_file.parent.mkdir(parents=True, exist_ok=True)
    # Sérialisation en mémoire puis écriture par Python : faiss.write_index passe par fopen(), qui échoue sous
    # Windows sur un chemin contenant des accents (« 1ere année »).
    index_file.write_bytes(faiss.serialize_index(index).tobytes())
    with open(chunks_file, "w", encoding="utf-8") as f:
        json.dump(chunks, f, ensure_ascii=False)
    manifest = {
        "embed_model": embed_model,
        "dimension": int(index.d),
        "chunks": len(chunks),
        "documents": len({c["doc_id"] for c in chunks}),
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        **(extra or {}),
    }
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return manifest


def load_store(index_file: Path, chunks_file: Path, manifest_file: Path) -> VectorStore:
    if not index_file.exists() or not chunks_file.exists():
        raise IndexNotFoundError(
            f"Index introuvable ({index_file}). Construisez-le avec :\n"
            "  python -m rag_cyber prepare --sample   (ou : download puis prepare)\n"
            "  python -m rag_cyber index"
        )
    index = faiss.deserialize_index(np.frombuffer(index_file.read_bytes(), dtype="uint8"))
    with open(chunks_file, encoding="utf-8") as f:
        chunks = json.load(f)
    manifest = {}
    if manifest_file.exists():
        with open(manifest_file, encoding="utf-8") as f:
            manifest = json.load(f)
    return VectorStore(index=index, chunks=chunks, manifest=manifest)
