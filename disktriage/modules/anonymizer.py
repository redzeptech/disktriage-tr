from __future__ import annotations

import os
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from .logging_utils import get_logger

logger = get_logger("anonymizer")


_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

_IPV6_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}\b"
    r"|\b[0-9A-Fa-f]{0,4}::[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){0,5}\b"
)

_WIN_USERS_RE = re.compile(r"(?i)\b([A-Z]:\\Users\\)([^\\]+)(\\?)")
_WIN_USERS_FWD_RE = re.compile(r"(?i)\b([A-Z]:/Users/)([^/]+)(/?)")


def _mask_windows_user_paths(s: str) -> str:
    s = _WIN_USERS_RE.sub(r"\1[HIDDEN]\3", s)
    s = _WIN_USERS_FWD_RE.sub(r"\1[HIDDEN]\3", s)
    return s


def _mask_home_path(s: str, home: str) -> str:
    if not home:
        return s

    home_bs = home.replace("/", "\\").rstrip("\\")
    home_fs = home.replace("\\", "/").rstrip("/")

    if home_bs:
        s = s.replace(home_bs + "\\", "C:\\Users\\[HIDDEN]\\")
        s = s.replace(home_bs, "C:\\Users\\[HIDDEN]")
    if home_fs:
        s = s.replace(home_fs + "/", "C:/Users/[HIDDEN]/")
        s = s.replace(home_fs, "C:/Users/[HIDDEN]")
    return s


def _mask_computername(s: str, computername: str) -> str:
    if not computername:
        return s
    return re.sub(re.escape(computername), "[HIDDEN_PC]", s, flags=re.IGNORECASE)


def _mask_username_tokens(s: str, username: str) -> str:
    if not username:
        return s
    s = re.sub(rf"(?i)\\{re.escape(username)}\\", r"\[HIDDEN]\\", s)
    s = re.sub(rf"(?i)/{re.escape(username)}/", "/[HIDDEN]/", s)
    s = re.sub(rf"(?i)\b{re.escape(username)}\b", "[HIDDEN_USER]", s)
    return s


def _mask_ips(s: str) -> str:
    s = _IPV4_RE.sub("[HIDDEN_IP]", s)
    s = _IPV6_RE.sub("[HIDDEN_IP]", s)
    return s


def anonymize_string(
    s: str,
    *,
    username: str = "",
    computername: str = "",
    home: str = "",
) -> str:
    if not s:
        return s

    out = s
    out = _mask_windows_user_paths(out)
    out = _mask_home_path(out, home)
    out = _mask_username_tokens(out, username)
    out = _mask_computername(out, computername)
    out = _mask_ips(out)
    return out


def anonymize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively anonymize a payload for safe sharing.

    Masks:
    - Windows user directory paths (C:\\Users\\<name>\\...)
    - current username/home path
    - computer name
    - IP addresses (IPv4/IPv6)
    """
    username = os.environ.get("USERNAME", "")
    computername = os.environ.get("COMPUTERNAME", "")
    try:
        home = str(Path.home())
    except Exception:
        home = ""

    def walk(x: Any) -> Any:
        if isinstance(x, str):
            return anonymize_string(x, username=username, computername=computername, home=home)
        if isinstance(x, bytes):
            return x
        if isinstance(x, Mapping):
            return {walk(k) if isinstance(k, str) else k: walk(v) for k, v in x.items()}
        if isinstance(x, Sequence) and not isinstance(x, (str, bytes, bytearray)):
            return [walk(v) for v in x]
        return x

    try:
        copied = deepcopy(payload)
    except Exception:
        copied = dict(payload)

    sanitized = walk(copied)
    if isinstance(sanitized, dict):
        sanitized.setdefault("anonymized", True)
    return sanitized  # type: ignore[return-value]

