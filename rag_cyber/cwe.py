"""Noms des faiblesses CWE, lus dans le catalogue XML officiel (cwe.mitre.org)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path


def parse_cwe_catalog(path: Path) -> dict[str, str]:
    """Associe « CWE-79 » à son nom officiel. Seules les faiblesses actives sont gardées."""
    names: dict[str, str] = {}
    for _, element in ET.iterparse(path, events=("end",)):  # noqa: S314
        if element.tag.rsplit("}", 1)[-1] != "Weakness":
            continue
        if element.get("Status") == "Deprecated":
            element.clear()
            continue
        cwe_id, name = element.get("ID"), element.get("Name")
        if cwe_id and name:
            names[f"CWE-{cwe_id}"] = name
        element.clear()
    return names
