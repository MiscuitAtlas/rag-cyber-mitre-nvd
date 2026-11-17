"""Extraction des CVE depuis un flux NVD au format JSON 2.0."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
IGNORED_CWE = {"NVD-CWE-noinfo", "NVD-CWE-Other"}


def english_description(cve: dict[str, Any]) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return (desc.get("value") or "").strip()
    return ""


def cvss_info(cve: dict[str, Any]) -> dict[str, Any]:
    """Score CVSS le plus récent disponible, en privilégiant l'évaluation « Primary » (celle du NVD)."""
    metrics = cve.get("metrics", {})
    for key in CVSS_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        chosen = next((m for m in entries if m.get("type") == "Primary"), entries[0])
        data = chosen.get("cvssData", {})
        return {
            "cvss_version": data.get("version"),
            "cvss_score": data.get("baseScore"),
            "severity": data.get("baseSeverity") or chosen.get("baseSeverity"),
            "cvss_vector": data.get("vectorString"),
            "cvss_source": chosen.get("source"),
        }
    return {"cvss_version": None, "cvss_score": None, "severity": None, "cvss_vector": None, "cvss_source": None}


def weaknesses(cve: dict[str, Any]) -> list[str]:
    values = [
        desc.get("value")
        for weakness in cve.get("weaknesses", [])
        for desc in weakness.get("description", [])
        if desc.get("value") and desc.get("value") not in IGNORED_CWE
    ]
    return list(dict.fromkeys(values))


def affected_products(cve: dict[str, Any]) -> list[str]:
    """Éditeur et produit (« vendor:product ») des CPE marqués vulnérables."""
    products = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parts = (match.get("criteria") or "").split(":")
                if len(parts) > 4:
                    products.append(f"{parts[3]}:{parts[4]}")
    return list(dict.fromkeys(products))


def extract_cves(feed: dict[str, Any]) -> list[dict[str, Any]]:
    cves = []
    for item in feed.get("vulnerabilities", []):
        cve = item.get("cve", {})
        if not cve.get("id") or cve.get("vulnStatus") == "Rejected":
            continue
        cves.append(
            {
                "cve_id": cve["id"],
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "status": cve.get("vulnStatus"),
                "description": english_description(cve),
                **cvss_info(cve),
                "weaknesses": weaknesses(cve),
                "products": affected_products(cve),
                "source": "nvd",
            }
        )
    return cves


def load_feed(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)
