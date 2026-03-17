from __future__ import annotations

"""
Tarayıcı geçmişi toplama modülü.

- Chrome/Edge: Chromium tabanlı `History` SQLite veritabanı
- Firefox: `places.sqlite`

Veritabanı dosyaları çoğu zaman kilitli olabildiği için önce geçici bir kopya
üzerinden okunur.
"""

import os
import shutil
import sqlite3
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass(frozen=True, slots=True)
class HistoryItem:
    url: str
    title: str
    visit_count: Optional[int]
    last_visit_utc: Optional[str]


@dataclass(frozen=True, slots=True)
class BrowserHistoryProfile:
    browser: str
    profile: str
    db_path: str
    items: List[HistoryItem]


def _iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _chromium_time_to_iso(microseconds_since_1601: int) -> Optional[str]:
    if not microseconds_since_1601:
        return None
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return _iso_utc(epoch + timedelta(microseconds=int(microseconds_since_1601)))


def _firefox_time_to_iso(value: int) -> Optional[str]:
    # Firefox stores times in microseconds since Unix epoch in many places.
    if not value:
        return None

    # Heuristics: if value is too small/large, interpret accordingly.
    # - microseconds: 1_600_000_000_000_000 ~ year 2020
    # - milliseconds: 1_600_000_000_000 ~ year 2020
    # - seconds:      1_600_000_000 ~ year 2020
    if value > 10**14:
        dt = datetime.fromtimestamp(value / 1_000_000, tz=timezone.utc)
    elif value > 10**11:
        dt = datetime.fromtimestamp(value / 1_000, tz=timezone.utc)
    else:
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
    return _iso_utc(dt)


def _copy_to_temp(src: Path) -> Path:
    tmp_dir = Path(tempfile.mkdtemp(prefix="disktriage_history_"))
    dst = tmp_dir / src.name
    shutil.copy2(src, dst)
    return dst


def _query_sqlite(db_path: Path, sql: str, params: Tuple[Any, ...]) -> Iterable[sqlite3.Row]:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(sql, params)
        yield from cur.fetchall()
    finally:
        conn.close()


def _collect_chromium_history(db_path: Path, max_items: int) -> List[HistoryItem]:
    sql = """
        SELECT url, COALESCE(title, '') AS title, visit_count, last_visit_time
        FROM urls
        ORDER BY last_visit_time DESC
        LIMIT ?
    """
    items: List[HistoryItem] = []
    for row in _query_sqlite(db_path, sql, (int(max_items),)):
        items.append(
            HistoryItem(
                url=str(row["url"] or ""),
                title=str(row["title"] or ""),
                visit_count=int(row["visit_count"]) if row["visit_count"] is not None else None,
                last_visit_utc=_chromium_time_to_iso(int(row["last_visit_time"] or 0)),
            )
        )
    return items


def _collect_firefox_history(db_path: Path, max_items: int) -> List[HistoryItem]:
    sql = """
        SELECT url,
               COALESCE(title, '') AS title,
               visit_count,
               last_visit_date
        FROM moz_places
        WHERE url IS NOT NULL
        ORDER BY last_visit_date DESC
        LIMIT ?
    """
    items: List[HistoryItem] = []
    for row in _query_sqlite(db_path, sql, (int(max_items),)):
        last_visit_raw = row["last_visit_date"]
        items.append(
            HistoryItem(
                url=str(row["url"] or ""),
                title=str(row["title"] or ""),
                visit_count=int(row["visit_count"]) if row["visit_count"] is not None else None,
                last_visit_utc=_firefox_time_to_iso(int(last_visit_raw)) if last_visit_raw is not None else None,
            )
        )
    return items


def _iter_chromium_profiles(user_data_dir: Path) -> Iterable[Tuple[str, Path]]:
    # Common profile dirs: Default, Profile 1, Profile 2, ...
    if not user_data_dir.exists():
        return

    candidates: List[Path] = []
    default = user_data_dir / "Default"
    if default.is_dir():
        candidates.append(default)

    for p in user_data_dir.glob("Profile *"):
        if p.is_dir():
            candidates.append(p)

    for profile_dir in sorted(candidates, key=lambda x: x.name.lower()):
        history = profile_dir / "History"
        if history.is_file():
            yield profile_dir.name, history


def _iter_firefox_profiles(profiles_dir: Path) -> Iterable[Tuple[str, Path]]:
    if not profiles_dir.exists():
        return

    for p in profiles_dir.glob("*"):
        if not p.is_dir():
            continue
        places = p / "places.sqlite"
        if places.is_file():
            yield p.name, places


def collect_browser_history(
    *,
    max_items_per_profile: int = 50,
    browsers: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    # Returns structured payload ready to embed in report.json
    browser_set = {b.lower() for b in (browsers or ["chrome", "edge", "firefox"])}
    result: Dict[str, Any] = {
        "enabled": True,
        "profiles": [],
        "profile_count": 0,
        "errors": [],
    }

    local = os.environ.get("LOCALAPPDATA")
    roaming = os.environ.get("APPDATA")
    if not local and not roaming:
        result["enabled"] = False
        result["errors"].append("LOCALAPPDATA/APPDATA ortam değişkenleri bulunamadı.")
        return result

    profiles: List[BrowserHistoryProfile] = []

    def add_profile(browser: str, profile: str, db_path: Path, kind: str) -> None:
        try:
            copied = _copy_to_temp(db_path)
            if kind == "chromium":
                items = _collect_chromium_history(copied, int(max_items_per_profile))
            else:
                items = _collect_firefox_history(copied, int(max_items_per_profile))

            profiles.append(
                BrowserHistoryProfile(
                    browser=browser,
                    profile=profile,
                    db_path=str(db_path),
                    items=items,
                )
            )
        except Exception as e:
            result["errors"].append(f"{browser}:{profile}: {type(e).__name__}")

    if "chrome" in browser_set and local:
        chrome_ud = Path(local) / "Google" / "Chrome" / "User Data"
        for profile_name, history_path in _iter_chromium_profiles(chrome_ud):
            add_profile("chrome", profile_name, history_path, "chromium")

    if "edge" in browser_set and local:
        edge_ud = Path(local) / "Microsoft" / "Edge" / "User Data"
        for profile_name, history_path in _iter_chromium_profiles(edge_ud):
            add_profile("edge", profile_name, history_path, "chromium")

    if "firefox" in browser_set and roaming:
        ff_profiles = Path(roaming) / "Mozilla" / "Firefox" / "Profiles"
        for profile_name, places_path in _iter_firefox_profiles(ff_profiles):
            add_profile("firefox", profile_name, places_path, "firefox")

    result["profiles"] = [
        {
            "browser": p.browser,
            "profile": p.profile,
            "db_path": p.db_path,
            "item_count": len(p.items),
            "items": [asdict(i) for i in p.items],
        }
        for p in profiles
    ]
    result["profile_count"] = len(profiles)
    return result

