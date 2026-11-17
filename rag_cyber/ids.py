"""Détection des identifiants de sécurité dans un texte (question ou réponse)."""

from __future__ import annotations

import re

# Bornes de mot explicites : « AT1053 » ou « CVE-2025-140370 » partiel ne doivent pas correspondre.
CVE_RE = re.compile(r"(?<![\w-])CVE-\d{4}-\d{4,}(?![\w-])", re.IGNORECASE)
ATTACK_RE = re.compile(r"(?<![\w.])T\d{4}(?:\.\d{3})?(?![\w]|\.\d)", re.IGNORECASE)
CWE_RE = re.compile(r"(?<![\w-])CWE-\d{1,5}(?![\w-])", re.IGNORECASE)
DET_RE = re.compile(r"(?<![\w])DET\d{4}(?![\w])", re.IGNORECASE)
MITIGATION_RE = re.compile(r"(?<![\w])M\d{4}(?![\w])")


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def find_lookup_ids(text: str) -> list[str]:
    """Identifiants qui désignent un document du corpus (CVE et techniques ATT&CK), dans l'ordre d'apparition."""
    found: list[tuple[int, str]] = []
    for pattern in (CVE_RE, ATTACK_RE):
        found.extend((m.start(), m.group(0).upper()) for m in pattern.finditer(text))
    return _unique([value for _, value in sorted(found)])


def find_all_ids(text: str) -> list[str]:
    """Tous les identifiants de sécurité cités (CVE, ATT&CK, CWE, stratégies de détection, mesures d'atténuation)."""
    found: list[tuple[int, str]] = []
    for pattern in (CVE_RE, ATTACK_RE, CWE_RE, DET_RE, MITIGATION_RE):
        found.extend((m.start(), m.group(0).upper()) for m in pattern.finditer(text))
    return _unique([value for _, value in sorted(found)])
