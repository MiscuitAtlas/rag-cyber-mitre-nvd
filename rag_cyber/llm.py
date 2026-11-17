"""Client minimal pour l'API locale d'Ollama (/api/chat), avec des erreurs explicites."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import requests


class LLMError(RuntimeError):
    """Erreur affichable telle quelle à l'utilisateur."""


class OllamaClient:
    def __init__(
        self,
        url: str = "http://127.0.0.1:11434",
        model: str = "mistral",
        temperature: float = 0.0,
        seed: int = 42,
        num_ctx: int = 4096,
        timeout: int = 180,
    ):
        self.url = url.rstrip("/")
        self.model = model
        self.timeout = timeout
        # Température 0 et graine fixe : réponses reproductibles d'une exécution à l'autre.
        self.options = {"temperature": temperature, "seed": seed, "num_ctx": num_ctx}

    def _post(self, messages: list[dict[str, str]], stream: bool) -> requests.Response:
        payload: dict[str, Any] = {"model": self.model, "messages": messages, "stream": stream, "options": self.options}
        try:
            response = requests.post(f"{self.url}/api/chat", json=payload, timeout=self.timeout, stream=stream)
        except requests.ConnectionError as exc:
            raise LLMError(
                f"Impossible de joindre Ollama sur {self.url}. Démarrez l'application Ollama ou lancez `ollama serve`."
            ) from exc
        except requests.Timeout as exc:
            raise LLMError(f"Ollama n'a pas répondu en {self.timeout} s (RAG_TIMEOUT pour allonger le délai).") from exc
        if response.status_code == 404:
            raise LLMError(
                f"Le modèle « {self.model} » n'est pas installé dans Ollama. Lancez `ollama pull {self.model}`."
            )
        if not response.ok:
            raise LLMError(f"Erreur Ollama {response.status_code} : {response.text[:300]}")
        return response

    def chat(self, messages: list[dict[str, str]]) -> str:
        data = self._post(messages, stream=False).json()
        if "error" in data:
            raise LLMError(f"Erreur Ollama : {data['error']}")
        return data.get("message", {}).get("content", "").strip()

    def stream_chat(self, messages: list[dict[str, str]]) -> Iterator[str]:
        response = self._post(messages, stream=True)
        try:
            for line in response.iter_lines():
                if not line:
                    continue
                data = json.loads(line)
                if "error" in data:
                    raise LLMError(f"Erreur Ollama : {data['error']}")
                piece = data.get("message", {}).get("content", "")
                if piece:
                    yield piece
                if data.get("done"):
                    break
        except requests.RequestException as exc:
            raise LLMError(f"Connexion à Ollama interrompue : {exc}") from exc
        finally:
            response.close()
