from __future__ import annotations

from datetime import datetime, timedelta, timezone


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def filetime_to_iso(filetime: int) -> str:
    if filetime <= 0:
        raise ValueError("filetime must be > 0")
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return (epoch + timedelta(microseconds=filetime / 10)).isoformat()

