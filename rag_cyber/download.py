"""Téléchargement des sources : ATT&CK (STIX), flux NVD récent et catalogue CWE."""

from __future__ import annotations

import gzip
import io
import shutil
import zipfile
from pathlib import Path

import requests

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
NVD_RECENT_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"


def _get(url: str, timeout: int = 180) -> bytes:
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    return response.content


def download_mitre(target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(_get(MITRE_URL))
    return target


def download_nvd_recent(target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(io.BytesIO(_get(NVD_RECENT_URL))) as source, open(target, "wb") as out:
        shutil.copyfileobj(source, out)
    return target


def download_cwe(target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(_get(CWE_URL))) as archive:
        xml_name = next(name for name in archive.namelist() if name.endswith(".xml"))
        with archive.open(xml_name) as source, open(target, "wb") as out:
            shutil.copyfileobj(source, out)
    return target
