from __future__ import annotations

import platform
import struct
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from .logging_utils import get_logger
from .utils import filetime_to_iso

logger = get_logger("userassist")


@dataclass(frozen=True, slots=True)
class UserAssistEntry:
    guid: str
    name: str
    run_count: Optional[int]
    last_run_utc: Optional[str]


def _rot13(s: str) -> str:
    # UserAssist value names are ROT13'd for ASCII A-Z/a-z.
    out = []
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:  # A-Z
            out.append(chr(((o - 65 + 13) % 26) + 65))
        elif 97 <= o <= 122:  # a-z
            out.append(chr(((o - 97 + 13) % 26) + 97))
        else:
            out.append(ch)
    return "".join(out)


def _parse_versioned_value(data: bytes, version: int) -> Tuple[Optional[int], Optional[str]]:
    # Based on winreg-kb: version 3 (16 bytes), version 5 (72 bytes).
    if not data:
        return None, None

    try:
        if version == 3:
            # Offset 4: executions (DWORD), offset 8: FILETIME (QWORD)
            if len(data) < 16:
                return None, None
            run_count = struct.unpack_from("<I", data, 4)[0]
            ft = struct.unpack_from("<Q", data, 8)[0]
            last = filetime_to_iso(int(ft)) if ft else None
            return int(run_count), last

        # version 5 (Win7+)
        if len(data) < 72:
            return None, None
        run_count = struct.unpack_from("<I", data, 4)[0]
        ft = struct.unpack_from("<Q", data, 60)[0]
        last = filetime_to_iso(int(ft)) if ft else None
        return int(run_count), last
    except Exception:
        logger.debug("Failed to parse UserAssist value", exc_info=True)
        return None, None


def collect_userassist(*, max_entries: int = 200) -> Dict[str, Any]:
    """
    Collects UserAssist execution traces from the live user registry (HKCU).
    This is best-effort; it will not crash on access/parse errors.
    """
    result: Dict[str, Any] = {
        "enabled": True,
        "entries": [],
        "entry_count": 0,
        "errors": [],
    }

    if platform.system().lower() != "windows":
        result["enabled"] = False
        result["errors"].append("UserAssist analizi sadece Windows üzerinde destekleniyor.")
        return result

    try:
        import winreg  # type: ignore
    except Exception:
        result["enabled"] = False
        result["errors"].append("winreg modülü bulunamadı.")
        return result

    base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    guid_keys: List[str] = []

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base) as k:
            i = 0
            while True:
                try:
                    guid_keys.append(winreg.EnumKey(k, i))
                    i += 1
                except OSError:
                    break
    except Exception as e:
        result["enabled"] = False
        result["errors"].append(f"HKCU UserAssist açılamadı: {type(e).__name__}")
        return result

    entries: List[UserAssistEntry] = []
    for guid in guid_keys:
        count_key = base + "\\" + guid + "\\Count"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, count_key) as ck:
                # Detect format version if present.
                version = 5
                try:
                    v, _t = winreg.QueryValueEx(ck, "Version")
                    if isinstance(v, int):
                        version = int(v)
                except Exception:
                    pass

                j = 0
                while True:
                    try:
                        name, value, vtype = winreg.EnumValue(ck, j)
                        j += 1
                    except OSError:
                        break

                    if name == "Version":
                        continue

                    decoded_name = _rot13(str(name))
                    run_count, last_run = _parse_versioned_value(value, version) if isinstance(value, (bytes, bytearray)) else (None, None)
                    entries.append(
                        UserAssistEntry(
                            guid=str(guid),
                            name=decoded_name,
                            run_count=run_count,
                            last_run_utc=last_run,
                        )
                    )
        except PermissionError:
            result["errors"].append(f"{guid}: erişim engellendi")
        except FileNotFoundError:
            continue
        except Exception as e:
            result["errors"].append(f"{guid}: {type(e).__name__}")

    # Sort by last_run desc, fallback run_count.
    def key(e: UserAssistEntry) -> Tuple[int, str, int]:
        if e.last_run_utc:
            return (0, e.last_run_utc, e.run_count or 0)
        return (1, "", e.run_count or 0)

    entries_sorted = sorted(entries, key=key, reverse=True)[: int(max_entries)]
    result["entries"] = [asdict(e) for e in entries_sorted]
    result["entry_count"] = len(entries_sorted)
    return result

