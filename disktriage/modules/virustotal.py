from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .logging_utils import get_logger

logger = get_logger("virustotal")


VT_FILE_URL = "https://www.virustotal.com/api/v3/files/"


@dataclass(frozen=True, slots=True)
class VTFileReport:
    sha256: str
    harmless: Optional[int]
    malicious: Optional[int]
    suspicious: Optional[int]
    undetected: Optional[int]
    timeout: Optional[int]
    reputation: Optional[int]
    meaningful_name: Optional[str]
    permalink: str
    error: Optional[str]


def _vt_key() -> Optional[str]:
    return os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")


def _http_get_json(url: str, *, headers: Dict[str, str], timeout_s: int = 15) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as r:
            raw = r.read()
        return json.loads(raw.decode("utf-8", errors="replace")), None
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return None, f"HTTPError {e.code}: {body[:200]}".strip()
    except Exception as e:
        return None, f"{type(e).__name__}"


def get_file_report(sha256: str, *, api_key: str, timeout_s: int = 15) -> VTFileReport:
    sha256 = (sha256 or "").strip().lower()
    url = VT_FILE_URL + sha256
    headers = {"x-apikey": api_key}

    data, err = _http_get_json(url, headers=headers, timeout_s=timeout_s)
    if err or not data:
        return VTFileReport(
            sha256=sha256,
            harmless=None,
            malicious=None,
            suspicious=None,
            undetected=None,
            timeout=None,
            reputation=None,
            meaningful_name=None,
            permalink=url,
            error=err or "empty_response",
        )

    try:
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        return VTFileReport(
            sha256=sha256,
            harmless=stats.get("harmless"),
            malicious=stats.get("malicious"),
            suspicious=stats.get("suspicious"),
            undetected=stats.get("undetected"),
            timeout=stats.get("timeout"),
            reputation=attrs.get("reputation"),
            meaningful_name=attrs.get("meaningful_name"),
            permalink=url,
            error=None,
        )
    except Exception as e:
        return VTFileReport(
            sha256=sha256,
            harmless=None,
            malicious=None,
            suspicious=None,
            undetected=None,
            timeout=None,
            reputation=None,
            meaningful_name=None,
            permalink=url,
            error=f"parse_error:{type(e).__name__}",
        )


def check_hashes(
    hashes: Sequence[str],
    *,
    per_request_delay_s: float = 0.25,
    timeout_s: int = 15,
    max_items: int = 25,
) -> Dict[str, Any]:
    """
    VirusTotal v3 "files/{hash}" endpoint üzerinden hash reputasyonu alır.

    - API key env: VT_API_KEY (veya VIRUSTOTAL_API_KEY)
    - Varsayılan olarak rate-limit'e takılmamak için küçük gecikme koyar.
    """
    api_key = _vt_key()
    result: Dict[str, Any] = {
        "enabled": True,
        "source": "virustotal:v3",
        "max_items": int(max_items),
        "checked": 0,
        "reports": [],
        "errors": [],
    }

    if not api_key:
        result["enabled"] = False
        result["errors"].append("VT_API_KEY (veya VIRUSTOTAL_API_KEY) ortam değişkeni tanımlı değil.")
        return result

    unique: List[str] = []
    seen = set()
    for h in hashes:
        hh = (h or "").strip().lower()
        if len(hh) != 64:
            continue
        if hh in seen:
            continue
        seen.add(hh)
        unique.append(hh)

    unique = unique[: int(max_items)]
    reports: List[VTFileReport] = []

    for idx, h in enumerate(unique):
        if idx and per_request_delay_s > 0:
            time.sleep(per_request_delay_s)
        rep = get_file_report(h, api_key=api_key, timeout_s=timeout_s)
        reports.append(rep)

    result["checked"] = len(reports)
    result["reports"] = [asdict(r) for r in reports]
    return result

