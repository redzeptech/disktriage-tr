from __future__ import annotations

import csv
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .logging_utils import get_logger

logger = get_logger("timeline")


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    timestamp_utc: str
    source: str
    event_type: str
    subject: str
    details: str


def _parse_iso(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _add(events: List[TimelineEvent], ts: Optional[str], source: str, event_type: str, subject: str, details: str) -> None:
    if not ts:
        return
    if _parse_iso(ts) is None:
        return
    events.append(
        TimelineEvent(
            timestamp_utc=ts,
            source=source,
            event_type=event_type,
            subject=subject,
            details=details,
        )
    )


def collect_timeline_events(payload: Dict[str, Any]) -> List[TimelineEvent]:
    """
    Payload içindeki tüm artifact verilerini birleştirip zaman tüneli event listesi üretir.
    Sıralama bu fonksiyonun dışında yapılır.
    """
    events: List[TimelineEvent] = []

    # Report creation (anchor)
    _add(events, payload.get("created_utc"), "report", "report_created", "report", "Rapor üretildi")

    # File system (inventory)
    summary = payload.get("summary") or {}
    for r in (summary.get("recently_modified_top50") or []):
        _add(events, r.get("mtime_utc"), "filesystem", "file_mtime", r.get("path") or "", "Modified time")
        _add(events, r.get("ctime_utc"), "filesystem", "file_ctime", r.get("path") or "", "Created/changed time")

    for r in (summary.get("biggest_files_top25") or []):
        _add(events, r.get("mtime_utc"), "filesystem", "file_mtime", r.get("path") or "", "Modified time (big file)")
        _add(events, r.get("ctime_utc"), "filesystem", "file_ctime", r.get("path") or "", "Created/changed time (big file)")

    # Prefetch
    pf = payload.get("prefetch") or {}
    for e in (pf.get("entries") or []):
        exe = e.get("executable") or ""
        for ts in (e.get("last_run_times_utc") or [])[:8]:
            _add(events, ts, "prefetch", "prefetch_last_run", exe, "Prefetch last run")
        _add(events, e.get("pf_mtime_utc"), "prefetch", "prefetch_file_mtime", exe, "Prefetch file mtime")

    # Browser history
    bh = payload.get("browser_history") or {}
    for p in (bh.get("profiles") or []):
        b = p.get("browser") or ""
        prof = p.get("profile") or ""
        for it in (p.get("items") or [])[:100]:
            url = it.get("url") or ""
            ts = it.get("last_visit_utc")
            _add(events, ts, "browser_history", "url_visit", f"{b}/{prof}", url)

    # EVTX
    evtx = payload.get("event_logs") or {}
    for e in (evtx.get("system_critical_errors") or []):
        ts = e.get("time_created_utc")
        provider = e.get("provider") or ""
        event_id = e.get("event_id")
        _add(events, ts, "evtx", "system_error", provider, f"EventID={event_id}")

    sec = (evtx.get("security_logons") or {}).get("events") or []
    for e in sec:
        ts = e.get("time_created_utc")
        event_id = e.get("event_id")
        user = (e.get("data") or {}).get("TargetUserName") or ""
        ip = (e.get("data") or {}).get("IpAddress") or ""
        _add(events, ts, "evtx", "security_logon", str(user), f"EventID={event_id} Ip={ip}")

    # UserAssist
    ua = payload.get("userassist") or {}
    for e in (ua.get("entries") or []):
        _add(events, e.get("last_run_utc"), "userassist", "userassist_last_run", e.get("name") or "", e.get("guid") or "")

    return events


def build_timeline(payload: Dict[str, Any], *, embed_max: int = 1000) -> Dict[str, Any]:
    events = collect_timeline_events(payload)
    events_sorted = sorted(events, key=lambda e: _parse_iso(e.timestamp_utc) or datetime.min, reverse=True)

    by_source: Dict[str, int] = {}
    for e in events_sorted:
        by_source[e.source] = by_source.get(e.source, 0) + 1

    return {
        "total_events": len(events_sorted),
        "by_source": dict(sorted(by_source.items(), key=lambda kv: kv[1], reverse=True)),
        "events": [asdict(e) for e in events_sorted[: int(embed_max)]],
    }


def write_timeline_csv(out_path: Path, events: List[TimelineEvent]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp_utc", "source", "event_type", "subject", "details"])
        for e in events:
            w.writerow([e.timestamp_utc, e.source, e.event_type, e.subject, e.details])


def sort_events_desc(events: List[TimelineEvent]) -> List[TimelineEvent]:
    return sorted(events, key=lambda e: _parse_iso(e.timestamp_utc) or datetime.min, reverse=True)

