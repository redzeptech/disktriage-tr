from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FileRecord:
    path: str
    size: int
    mtime_utc: str
    ctime_utc: str

