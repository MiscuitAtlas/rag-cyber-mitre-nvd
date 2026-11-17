"""Configuration centralisée, lue dans les variables d'environnement (et le fichier .env)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _int(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value not in (None, "") else default


def _float(name: str, default: float) -> float:
    value = os.getenv(name)
    return float(value) if value not in (None, "") else default


@dataclass(frozen=True)
class Settings:
    """Tous les réglages du projet. Chaque champ peut être surchargé par une variable d'environnement."""

    raw_dir: Path = field(default_factory=lambda: Path(os.getenv("RAG_RAW_DIR", "data/raw")))
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("RAG_DATA_DIR", "data/processed")))
    index_dir: Path = field(default_factory=lambda: Path(os.getenv("RAG_INDEX_DIR", "vectorstore/faiss_index")))
    eval_dir: Path = field(default_factory=lambda: Path(os.getenv("RAG_EVAL_DIR", "data/eval")))

    embed_model: str = field(
        default_factory=lambda: os.getenv("RAG_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
    )
    chunk_size: int = field(default_factory=lambda: _int("RAG_CHUNK_SIZE", 120))
    chunk_overlap: int = field(default_factory=lambda: _int("RAG_CHUNK_OVERLAP", 30))
    top_k: int = field(default_factory=lambda: _int("RAG_TOP_K", 5))
    candidates: int = field(default_factory=lambda: _int("RAG_CANDIDATES", 10))
    hybrid_alpha: float = field(default_factory=lambda: _float("RAG_HYBRID_ALPHA", 0.6))

    ollama_url: str = field(default_factory=lambda: os.getenv("OLLAMA_URL", "http://127.0.0.1:11434"))
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "mistral"))
    temperature: float = field(default_factory=lambda: _float("RAG_TEMPERATURE", 0.0))
    seed: int = field(default_factory=lambda: _int("RAG_SEED", 42))
    num_ctx: int = field(default_factory=lambda: _int("RAG_NUM_CTX", 4096))
    timeout: int = field(default_factory=lambda: _int("RAG_TIMEOUT", 180))

    # Fichiers dérivés
    @property
    def mitre_raw(self) -> Path:
        return self.raw_dir / "mitre" / "enterprise-attack.json"

    @property
    def nvd_raw(self) -> Path:
        return self.raw_dir / "nvd" / "nvdcve-2.0-recent.json"

    @property
    def cwe_raw(self) -> Path:
        return self.raw_dir / "cwe" / "cwec_latest.xml"

    @property
    def techniques_file(self) -> Path:
        return self.data_dir / "mitre_techniques.json"

    @property
    def cves_file(self) -> Path:
        return self.data_dir / "nvd_recent_cves.json"

    @property
    def cwe_file(self) -> Path:
        return self.data_dir / "cwe_names.json"

    @property
    def documents_file(self) -> Path:
        return self.data_dir / "rag_documents.json"

    @property
    def chunks_file(self) -> Path:
        return self.data_dir / "rag_chunks.json"

    @property
    def index_file(self) -> Path:
        return self.index_dir / "full.index"

    @property
    def index_chunks_file(self) -> Path:
        return self.index_dir / "full_chunks.json"

    @property
    def manifest_file(self) -> Path:
        return self.index_dir / "manifest.json"

    @property
    def questions_file(self) -> Path:
        return self.eval_dir / "questions.json"

    @property
    def results_dir(self) -> Path:
        return self.eval_dir / "results"


def get_settings(**overrides) -> Settings:
    """Renvoie la configuration, avec des valeurs éventuellement forcées (utile en ligne de commande et en test)."""
    settings = Settings()
    if not overrides:
        return settings
    values = {name: getattr(settings, name) for name in settings.__dataclass_fields__}
    values.update({key: value for key, value in overrides.items() if value is not None})
    return Settings(**values)
