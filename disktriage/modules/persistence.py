from __future__ import annotations

import csv
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .io import safe_stat
from .logging_utils import get_logger
from .utils import filetime_to_iso, to_iso

logger = get_logger("persistence")


_TEMP_HINT_RE = re.compile(r"(?i)\\appdata\\local\\temp\\|\\temp\\|/appdata/local/temp/|/temp/")
_USER_WRITABLE_RE = re.compile(r"(?i)\\users\\[^\\]+\\appdata\\|\\users\\[^\\]+\\downloads\\|/users/[^/]+/appdata/|/users/[^/]+/downloads/")


@dataclass(frozen=True, slots=True)
class Finding:
    kind: str  # run_key | startup_folder | service | scheduled_task
    name: str
    command: str
    exec_path: Optional[str]
    signature: Optional[str]
    suspicious: bool
    suspicious_reasons: List[str]
    timestamp_utc: Optional[str]


def _parse_iso(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _decode_best_effort(b: bytes) -> str:
    if not b:
        return ""
    for enc in ("utf-8", "utf-16", "mbcs"):
        try:
            return b.decode(enc, errors="replace")
        except Exception:
            continue
    return b.decode(errors="replace")


def _extract_exec_path(command: str) -> Optional[str]:
    if not command:
        return None
    s = command.strip()

    # Expand environment variables if present.
    try:
        s = os.path.expandvars(s)
    except Exception:
        pass

    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 1:
            return s[1:end]
    return s.split(" ", 1)[0]


def _authenticode_status(path: str) -> Optional[str]:
    """
    Best-effort signature check via PowerShell Get-AuthenticodeSignature.
    Returns: Valid | NotSigned | UnknownError | ... or None if cannot determine.
    """
    p = Path(path)
    if not p.exists() or not p.is_file():
        return None
    if p.suffix.lower() not in (".exe", ".dll", ".sys"):
        return None

    ps = (
        "powershell",
        "-NoProfile",
        "-Command",
        f"(Get-AuthenticodeSignature -FilePath {json.dumps(str(p))} -ErrorAction SilentlyContinue).Status",
    )
    try:
        r = subprocess.run(ps, capture_output=True, timeout=8)
        out = _decode_best_effort(r.stdout).strip()
        if out:
            return out
        return None
    except Exception:
        return None


def _is_suspicious_path(exec_path: Optional[str]) -> List[str]:
    if not exec_path:
        return ["missing_exec_path"]

    reasons: List[str] = []
    low = exec_path.lower()
    if _TEMP_HINT_RE.search(exec_path):
        reasons.append("runs_from_temp")
    if _USER_WRITABLE_RE.search(exec_path):
        reasons.append("runs_from_user_writable_dir")
    if any(low.endswith(ext) for ext in (".vbs", ".js", ".jse", ".ps1", ".bat", ".cmd", ".hta")):
        reasons.append("script_extension")

    # Missing file on disk
    try:
        p = Path(exec_path)
        if not p.exists():
            reasons.append("file_not_found")
    except Exception:
        pass

    return reasons


def _maybe_check_signature(
    exec_path: Optional[str],
    *,
    cache: Dict[str, Optional[str]],
    remaining_budget: List[int],
    only_if_suspicious: bool,
    suspicious_reasons: List[str],
) -> Optional[str]:
    if not exec_path:
        return None

    p = str(exec_path)
    if p in cache:
        return cache[p]

    if remaining_budget[0] <= 0:
        cache[p] = None
        return None

    should = True
    if only_if_suspicious:
        should = bool(suspicious_reasons) and Path(p).suffix.lower() in (".exe", ".dll", ".sys")

    if not should:
        cache[p] = None
        return None

    remaining_budget[0] -= 1
    sig = _authenticode_status(p)
    cache[p] = sig
    return sig


def _read_run_keys() -> List[Tuple[str, str, str]]:
    """
    Returns tuples: (hive, value_name, command)
    """
    results: List[Tuple[str, str, str]] = []

    try:
        import winreg  # type: ignore
    except Exception:
        return results

    run_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
    ]

    views = [
        ("64", 0),
        ("32", getattr(winreg, "KEY_WOW64_32KEY", 0)),
    ]

    for hive, subkey, hive_name in run_paths:
        for view_name, view_flag in views:
            access = winreg.KEY_READ | view_flag
            try:
                with winreg.OpenKey(hive, subkey, 0, access) as k:
                    i = 0
                    while True:
                        try:
                            name, value, _t = winreg.EnumValue(k, i)
                            i += 1
                        except OSError:
                            break
                        if not name:
                            continue
                        if isinstance(value, str) and value.strip():
                            results.append((f"{hive_name}:{view_name}", str(name), str(value)))
            except FileNotFoundError:
                continue
            except PermissionError:
                results.append((f"{hive_name}:{view_name}", subkey, "[ACCESS_DENIED]"))
            except Exception:
                logger.debug("Run key read failed: %s %s", hive_name, subkey, exc_info=True)

    return results


def _startup_folder_entries() -> List[Tuple[str, str]]:
    """
    Returns tuples: (name, full_path)
    """
    entries: List[Tuple[str, str]] = []

    appdata = os.environ.get("APPDATA") or ""
    programdata = os.environ.get("ProgramData") or ""
    candidates: List[Path] = []

    if appdata:
        candidates.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    if programdata:
        candidates.append(Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")

    for folder in candidates:
        try:
            if not folder.exists() or not folder.is_dir():
                continue
            for p in folder.iterdir():
                if p.is_file():
                    entries.append((p.name, str(p)))
        except Exception:
            logger.debug("Startup folder walk failed: %s", folder, exc_info=True)

    return entries


def _services_via_powershell() -> List[Dict[str, Any]]:
    ps = (
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,DisplayName,PathName,StartMode,State,StartName | "
        "ConvertTo-Json -Depth 3",
    )
    try:
        r = subprocess.run(ps, capture_output=True, timeout=20)
        out = _decode_best_effort(r.stdout).strip()
        if not out:
            return []
        data = json.loads(out)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
        return []
    except Exception:
        logger.debug("Service query failed", exc_info=True)
        return []


def _service_reg_last_write_utc(service_name: str) -> Optional[str]:
    try:
        import winreg  # type: ignore
    except Exception:
        return None

    key_path = rf"SYSTEM\CurrentControlSet\Services\{service_name}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as k:
            _subkeys, _values, last_write = winreg.QueryInfoKey(k)
            if last_write:
                # last_write is FILETIME in 100ns intervals since 1601-01-01
                return filetime_to_iso(int(last_write))
    except Exception:
        return None
    return None


def _schtasks_query_csv() -> List[Dict[str, str]]:
    cmd = ("schtasks", "/query", "/fo", "CSV", "/v")
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=25)
        out = _decode_best_effort(r.stdout)
        lines = [ln for ln in out.splitlines() if ln.strip()]
        if not lines:
            return []
        reader = csv.DictReader(lines)
        return [dict(row) for row in reader]
    except Exception:
        logger.debug("schtasks query failed", exc_info=True)
        return []


def _parse_schtasks_time(s: str) -> Optional[str]:
    s = (s or "").strip()
    if not s or s.lower() in ("n/a", "never"):
        return None
    # schtasks uses local format; best-effort parse known patterns
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%d.%m.%Y %H:%M:%S", "%d.%m.%Y %H:%M"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except Exception:
            continue
    return None


def collect_persistence(
    *,
    new_service_days: int = 7,
    sig_check_max: int = 50,
) -> Dict[str, Any]:
    """
    Startup (Run keys + Startup folder) + Services + Scheduled Tasks.
    Marks suspicious items based on:
    - runs from Temp / user-writable dirs
    - missing file
    - not signed (best-effort, limited budget)
    - new/modified service keys within last N days
    """
    result: Dict[str, Any] = {
        "enabled": True,
        "run_keys": [],
        "startup_folder": [],
        "services": {"new_days": int(new_service_days), "items": []},
        "scheduled_tasks": [],
        "suspicious": [],
        "errors": [],
    }

    if os.name != "nt":
        result["enabled"] = False
        result["errors"].append("Bu modül sadece Windows üzerinde destekleniyor.")
        return result

    sig_cache: Dict[str, Optional[str]] = {}
    budget = [int(sig_check_max)]

    findings: List[Finding] = []

    # Run keys
    for hive, name, cmdline in _read_run_keys():
        exec_path = _extract_exec_path(cmdline) if cmdline != "[ACCESS_DENIED]" else None
        reasons = _is_suspicious_path(exec_path) if cmdline != "[ACCESS_DENIED]" else ["access_denied"]
        sig = _maybe_check_signature(exec_path, cache=sig_cache, remaining_budget=budget, only_if_suspicious=True, suspicious_reasons=reasons)
        if sig in ("NotSigned", "UnknownError"):
            reasons.append(f"signature_{sig}")
        suspicious = bool(reasons)
        findings.append(
            Finding(
                kind="run_key",
                name=f"{hive}:{name}",
                command=cmdline,
                exec_path=exec_path,
                signature=sig,
                suspicious=suspicious,
                suspicious_reasons=reasons,
                timestamp_utc=None,
            )
        )

    # Startup folder
    for name, path in _startup_folder_entries():
        exec_path = str(path)
        reasons = _is_suspicious_path(exec_path)
        sig = _maybe_check_signature(exec_path, cache=sig_cache, remaining_budget=budget, only_if_suspicious=False, suspicious_reasons=reasons)
        if sig in ("NotSigned", "UnknownError"):
            reasons.append(f"signature_{sig}")
        st = safe_stat(Path(path))
        ts = to_iso(st.st_mtime) if st else None
        findings.append(
            Finding(
                kind="startup_folder",
                name=name,
                command=str(path),
                exec_path=exec_path,
                signature=sig,
                suspicious=bool(reasons),
                suspicious_reasons=reasons,
                timestamp_utc=ts,
            )
        )

    # Services
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=int(new_service_days))
    services = _services_via_powershell()
    for s in services:
        name = str(s.get("Name") or "")
        path_name = str(s.get("PathName") or "")
        exec_path = _extract_exec_path(path_name)
        last_write_utc = _service_reg_last_write_utc(name) if name else None

        reasons = _is_suspicious_path(exec_path)
        if last_write_utc:
            dt = _parse_iso(last_write_utc)
            if dt and dt >= cutoff:
                reasons.append("service_recently_modified")
        sig = _maybe_check_signature(exec_path, cache=sig_cache, remaining_budget=budget, only_if_suspicious=True, suspicious_reasons=reasons)
        if sig in ("NotSigned", "UnknownError"):
            reasons.append(f"signature_{sig}")

        findings.append(
            Finding(
                kind="service",
                name=name or str(s.get("DisplayName") or ""),
                command=path_name,
                exec_path=exec_path,
                signature=sig,
                suspicious=bool(reasons),
                suspicious_reasons=reasons,
                timestamp_utc=last_write_utc,
            )
        )

    # Scheduled tasks
    tasks = _schtasks_query_csv()
    for t in tasks:
        task_name = (t.get("TaskName") or t.get("Task Name") or "").strip()
        task_to_run = (t.get("Task To Run") or t.get("Actions") or "").strip()
        last_run = _parse_schtasks_time(t.get("Last Run Time") or "")

        exec_path = _extract_exec_path(task_to_run)
        reasons = _is_suspicious_path(exec_path)
        sig = _maybe_check_signature(exec_path, cache=sig_cache, remaining_budget=budget, only_if_suspicious=True, suspicious_reasons=reasons)
        if sig in ("NotSigned", "UnknownError"):
            reasons.append(f"signature_{sig}")

        findings.append(
            Finding(
                kind="scheduled_task",
                name=task_name or "(unnamed_task)",
                command=task_to_run,
                exec_path=exec_path,
                signature=sig,
                suspicious=bool(reasons),
                suspicious_reasons=reasons,
                timestamp_utc=last_run,
            )
        )

    # Build per-section output + top suspicious
    run_keys = [asdict(f) for f in findings if f.kind == "run_key"]
    startup_folder = [asdict(f) for f in findings if f.kind == "startup_folder"]
    services_out = [asdict(f) for f in findings if f.kind == "service"]
    tasks_out = [asdict(f) for f in findings if f.kind == "scheduled_task"]
    suspicious = [asdict(f) for f in findings if f.suspicious]

    def sort_ts_desc(x: Dict[str, Any]) -> Tuple[int, str]:
        ts = x.get("timestamp_utc")
        return (0, str(ts)) if ts else (1, "")

    result["run_keys"] = run_keys
    result["startup_folder"] = sorted(startup_folder, key=sort_ts_desc)
    result["services"]["items"] = sorted(services_out, key=sort_ts_desc)
    result["scheduled_tasks"] = sorted(tasks_out, key=sort_ts_desc)
    result["suspicious"] = suspicious[:300]
    result["signature_checks_performed"] = int(sig_check_max) - budget[0]
    return result

