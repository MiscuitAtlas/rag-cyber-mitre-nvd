"""Extraction des techniques MITRE ATT&CK Enterprise depuis le bundle STIX 2.1 (dépôt mitre/cti).

Depuis ATT&CK v18, la détection n'est plus décrite dans les champs ``x_mitre_detection`` et
``x_mitre_data_sources`` des techniques (vides) mais dans des objets dédiés :

    x-mitre-detection-strategy --detects--> attack-pattern
    x-mitre-detection-strategy --x_mitre_analytic_refs--> x-mitre-analytic
    x-mitre-analytic --x_mitre_log_source_references--> x-mitre-data-component

Ce module suit ces relations. Les anciens champs sont conservés en repli pour les bundles antérieurs.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

MITRE_SOURCE = "mitre-attack"


def _is_active(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == MITRE_SOURCE and ref.get("external_id"):
            return ref["external_id"]
    return None


def _url(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == MITRE_SOURCE and ref.get("url"):
            return ref["url"]
    return None


def extract_techniques(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Renvoie une fiche par technique ou sous-technique active, enrichie de sa détection et de ses mesures."""
    objects = bundle.get("objects", [])
    by_id = {obj["id"]: obj for obj in objects if "id" in obj}

    tactic_names = {
        obj.get("x_mitre_shortname"): obj.get("name")
        for obj in objects
        if obj.get("type") == "x-mitre-tactic" and _is_active(obj)
    }
    component_names = {obj["id"]: obj.get("name") for obj in objects if obj.get("type") == "x-mitre-data-component"}

    detections: dict[str, list[dict[str, Any]]] = defaultdict(list)
    mitigations: dict[str, list[dict[str, Any]]] = defaultdict(list)
    legacy_components: dict[str, list[str]] = defaultdict(list)

    for rel in objects:
        if rel.get("type") != "relationship" or not _is_active(rel):
            continue
        source = by_id.get(rel.get("source_ref", ""))
        target_id = rel.get("target_ref", "")
        if source is None or not _is_active(source):
            continue

        if rel.get("relationship_type") == "detects":
            if source.get("type") == "x-mitre-detection-strategy":
                detections[target_id].append(_detection_strategy(source, by_id, component_names))
            elif source.get("type") == "x-mitre-data-component":  # bundles antérieurs à v18
                legacy_components[target_id].append(source.get("name", ""))
        elif rel.get("relationship_type") == "mitigates" and source.get("type") == "course-of-action":
            mitigations[target_id].append(
                {
                    "id": _external_id(source),
                    "name": source.get("name"),
                    "description": (rel.get("description") or "").strip(),
                }
            )

    techniques = []
    attack_patterns = [obj for obj in objects if obj.get("type") == "attack-pattern" and _is_active(obj)]
    names_by_attack_id = {_external_id(obj): obj.get("name") for obj in attack_patterns}

    for obj in attack_patterns:
        attack_id = _external_id(obj)
        if not attack_id:
            continue
        is_sub = bool(obj.get("x_mitre_is_subtechnique", False))
        parent_id = attack_id.split(".")[0] if is_sub else None
        tactics = [
            tactic_names.get(phase.get("phase_name"), phase.get("phase_name"))
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == MITRE_SOURCE
        ]
        techniques.append(
            {
                "attack_id": attack_id,
                "name": obj.get("name"),
                "url": _url(obj),
                "is_subtechnique": is_sub,
                "parent_id": parent_id,
                "parent_name": names_by_attack_id.get(parent_id) if parent_id else None,
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []),
                "description": (obj.get("description") or "").strip(),
                "detection_strategies": sorted(detections.get(obj["id"], []), key=lambda d: d.get("id") or ""),
                "mitigations": sorted(mitigations.get(obj["id"], []), key=lambda m: m.get("id") or ""),
                # Champs historiques (ATT&CK < v18), vides dans les versions récentes
                "legacy_detection": (obj.get("x_mitre_detection") or "").strip(),
                "legacy_data_sources": obj.get("x_mitre_data_sources", [])
                or sorted(set(legacy_components.get(obj["id"], []))),
            }
        )

    return sorted(techniques, key=lambda t: t["attack_id"])


def _detection_strategy(
    strategy: dict[str, Any], by_id: dict[str, Any], component_names: dict[str, str]
) -> dict[str, Any]:
    analytics = []
    for ref in strategy.get("x_mitre_analytic_refs", []):
        analytic = by_id.get(ref)
        if analytic is None or not _is_active(analytic):
            continue
        log_sources = []
        for source in analytic.get("x_mitre_log_source_references", []):
            component = component_names.get(source.get("x_mitre_data_component_ref", ""))
            log_sources.append(
                {
                    "data_component": component,
                    "name": source.get("name"),
                    "channel": source.get("channel"),
                }
            )
        analytics.append(
            {
                "id": _external_id(analytic) or analytic.get("name"),
                "platforms": analytic.get("x_mitre_platforms", []),
                "description": (analytic.get("description") or "").strip(),
                "log_sources": log_sources,
            }
        )
    return {"id": _external_id(strategy), "name": strategy.get("name"), "analytics": analytics}


def load_bundle(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)
