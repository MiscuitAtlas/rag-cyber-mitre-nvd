"""Construction des documents du corpus (une technique ou une CVE par document) et découpage en chunks.

Chaque document est formé de sections (fiche, description, détection, atténuation). Le découpage respecte ces
sections et chaque chunk commence par une ligne d'en-tête (« T1053.005 Scheduled Task | Detection ») : un chunk
isolé reste ainsi identifiable, par le modèle d'embeddings comme par le LLM.
"""

from __future__ import annotations

import re
from typing import Any

_CITATION_RE = re.compile(r"\s*\(Citation:[^)]*\)")
_ATTACK_LINK_RE = re.compile(r"\[([^\]]+)\]\(https?://attack\.mitre\.org/techniques/(T\d{4})(?:/(\d{3}))?/?\)")
_LINK_RE = re.compile(r"\[([^\]]+)\]\((?:https?://[^)]+)\)")
_TAG_RE = re.compile(r"</?(?:code|b|i|br)\s*/?>", re.IGNORECASE)


def clean_text(text: str | None) -> str:
    """Retire les citations et les liens Markdown d'ATT&CK, en gardant l'ID des techniques citées."""
    if not text:
        return ""
    text = _CITATION_RE.sub("", text)
    text = _ATTACK_LINK_RE.sub(lambda m: f"{m.group(1)} ({m.group(2)}{'.' + m.group(3) if m.group(3) else ''})", text)
    text = _LINK_RE.sub(r"\1", text)
    text = _TAG_RE.sub("", text)
    paragraphs = [" ".join(p.split()) for p in re.split(r"\n\s*\n", text)]
    return "\n\n".join(p for p in paragraphs if p)


def _join(values: list[Any] | None, default: str = "unknown") -> str:
    values = [str(v) for v in (values or []) if v not in (None, "")]
    return ", ".join(values) if values else default


# --- MITRE ATT&CK ---------------------------------------------------------------------------------------------


def _detection_text(tech: dict[str, Any]) -> str:
    paragraphs = []
    for strategy in tech.get("detection_strategies", []):
        paragraphs.append(f"Detection strategy {strategy.get('id')}: {strategy.get('name')}.")
        for analytic in strategy.get("analytics", []):
            sources = []
            for source in analytic.get("log_sources", []):
                label = source.get("name") or ""
                if source.get("channel"):
                    label += f" ({source['channel']})"
                if source.get("data_component"):
                    label += f" [{source['data_component']}]"
                sources.append(label.strip())
            text = f"Analytic {analytic.get('id')} ({_join(analytic.get('platforms'))}): {clean_text(analytic.get('description'))}"
            if sources:
                text += f" Log sources: {'; '.join(sources)}."
            paragraphs.append(text)
    # Bundles antérieurs à ATT&CK v18
    if tech.get("legacy_detection"):
        paragraphs.append(clean_text(tech["legacy_detection"]))
    if tech.get("legacy_data_sources"):
        paragraphs.append(f"Data sources: {_join(tech['legacy_data_sources'])}.")
    return "\n\n".join(paragraphs)


def technique_document(tech: dict[str, Any]) -> dict[str, Any]:
    attack_id, name = tech["attack_id"], tech.get("name") or ""
    if tech.get("is_subtechnique"):
        kind = f"Sub-technique of {tech.get('parent_id')} ({tech.get('parent_name') or 'unknown'})"
    else:
        kind = "Technique"
    strategies = tech.get("detection_strategies", [])
    mitigations = tech.get("mitigations", [])

    overview = [
        f"MITRE ATT&CK technique {attack_id}: {name}.",
        f"Type: {kind}.",
        f"Tactics: {_join(tech.get('tactics'))}.",
        f"Platforms: {_join(tech.get('platforms'))}.",
    ]
    if strategies:
        overview.append(
            "Detection strategies: " + "; ".join(f"{s.get('id')} {s.get('name')}" for s in strategies) + "."
        )
    if mitigations:
        overview.append("Mitigations: " + "; ".join(f"{m.get('id')} {m.get('name')}" for m in mitigations) + ".")
    if tech.get("url"):
        overview.append(f"Reference: {tech['url']}")

    sections = [("Overview", " ".join(overview)), ("Description", clean_text(tech.get("description")))]
    detection = _detection_text(tech)
    if detection:
        sections.append(("Detection", detection))
    mitigation_text = "\n\n".join(
        f"Mitigation {m.get('id')} {m.get('name')}: {clean_text(m.get('description'))}".rstrip(": ")
        for m in mitigations
    )
    if mitigation_text:
        sections.append(("Mitigations", mitigation_text))

    return {
        "doc_id": f"mitre:{attack_id}",
        "source": "mitre",
        "title": f"{attack_id} {name}",
        "sections": [{"name": n, "text": t} for n, t in sections if t],
        "metadata": {
            "attack_id": attack_id,
            "name": name,
            "is_subtechnique": bool(tech.get("is_subtechnique")),
            "parent_id": tech.get("parent_id"),
            "tactics": tech.get("tactics", []),
            "url": tech.get("url"),
        },
    }


# --- CVE ------------------------------------------------------------------------------------------------------


def cve_document(cve: dict[str, Any], cwe_names: dict[str, str] | None = None) -> dict[str, Any]:
    cwe_names = cwe_names or {}
    cve_id = cve["cve_id"]
    weaknesses = [f"{w} ({cwe_names[w]})" if w in cwe_names else w for w in cve.get("weaknesses", [])]
    score = cve.get("cvss_score")
    version = cve.get("cvss_version")
    cvss = "unknown" if score is None else f"{score}" + (f" (CVSS v{version})" if version else "")

    overview = [
        f"Vulnerability {cve_id}.",
        f"Severity: {cve.get('severity') or 'unknown'}.",
        f"CVSS base score: {cvss}.",
    ]
    if cve.get("cvss_vector"):
        overview.append(f"CVSS vector: {cve['cvss_vector']}.")
    overview.append(f"Weaknesses (CWE): {_join(weaknesses)}.")
    if cve.get("products"):
        overview.append(f"Affected products (vendor:product): {_join(cve['products'][:10])}.")
    overview.append(
        f"Published: {(cve.get('published') or 'unknown')[:10]}. Last modified: {(cve.get('last_modified') or 'unknown')[:10]}."
    )

    sections = [("Overview", " ".join(overview)), ("Description", clean_text(cve.get("description")))]
    return {
        "doc_id": f"cve:{cve_id}",
        "source": "nvd",
        "title": cve_id,
        "sections": [{"name": n, "text": t} for n, t in sections if t],
        "metadata": {
            "cve_id": cve_id,
            "severity": cve.get("severity"),
            "cvss_score": score,
            "weaknesses": cve.get("weaknesses", []),
        },
    }


def build_documents(
    techniques: list[dict[str, Any]], cves: list[dict[str, Any]], cwe_names: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    return [technique_document(t) for t in techniques] + [cve_document(c, cwe_names) for c in cves]


# --- Découpage ------------------------------------------------------------------------------------------------


def split_words(words: list[str], size: int, overlap: int) -> list[list[str]]:
    """Fenêtres glissantes de ``size`` mots avec ``overlap`` mots communs entre deux fenêtres."""
    if size <= 0 or not 0 <= overlap < size:
        raise ValueError("Il faut size > 0 et 0 <= overlap < size.")
    windows, start = [], 0
    while start < len(words):
        windows.append(words[start : start + size])
        if start + size >= len(words):
            break
        start += size - overlap
    return windows


def chunk_section(text: str, size: int, overlap: int) -> list[str]:
    """Regroupe les paragraphes entiers tant qu'ils tiennent dans ``size`` mots ; découpe les plus longs."""
    pieces: list[str] = []
    current: list[str] = []
    for paragraph in text.split("\n\n"):
        words = paragraph.split()
        if not words:
            continue
        if len(words) > size:
            if current:
                pieces.append(" ".join(current))
                current = []
            pieces.extend(" ".join(w) for w in split_words(words, size, overlap))
        elif len(current) + len(words) > size:
            pieces.append(" ".join(current))
            current = list(words)
        else:
            current.extend(words)
    if current:
        pieces.append(" ".join(current))
    return pieces


def chunk_documents(documents: list[dict[str, Any]], size: int = 120, overlap: int = 30) -> list[dict[str, Any]]:
    chunks = []
    for doc in documents:
        position = 0
        for section in doc["sections"]:
            for piece in chunk_section(section["text"], size, overlap):
                chunks.append(
                    {
                        "chunk_id": f"{doc['doc_id']}#{position}",
                        "doc_id": doc["doc_id"],
                        "source": doc["source"],
                        "section": section["name"],
                        "text": f"{doc['title']} | {section['name']}\n{piece}",
                        "metadata": doc["metadata"],
                    }
                )
                position += 1
    return chunks
