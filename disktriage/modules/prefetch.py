from __future__ import annotations

import binascii
import os
import platform
import struct
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import io
from .utils import filetime_to_iso


@dataclass(frozen=True, slots=True)
class PrefetchEntry:
    pf_path: str
    executable: str
    format_version: Optional[int]
    prefetch_hash: Optional[int]
    run_count: Optional[int]
    last_run_times_utc: List[str]
    pf_mtime_utc: str
    pf_size: int


def _utc_iso_from_stat_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def default_prefetch_dir() -> Path:
    system_root = os.environ.get("SystemRoot") or r"C:\Windows"
    return Path(system_root) / "Prefetch"


def _parse_executable_from_pf_filename(pf_path: Path) -> str:
    stem = pf_path.stem
    # Common format: EXE_NAME-<HASH>.pf
    if "-" in stem:
        left, _ = stem.rsplit("-", 1)
        if left:
            return left
    return stem


def _decode_utf16le_zstr(b: bytes) -> str:
    try:
        s = b.decode("utf-16le", errors="ignore")
    except Exception:
        return ""
    return s.split("\x00", 1)[0].strip()


def _maybe_decompress_mam(raw: bytes) -> Optional[bytes]:
    # MAM compressed prefetch: signature is "MAM\x04" (and variants with checksum bit).
    if len(raw) < 8:
        return None

    signature, decompressed_size = struct.unpack_from("<II", raw, 0)
    calgo = (signature & 0x0F000000) >> 24
    crcck = (signature & 0xF0000000) >> 28
    magic = signature & 0x00FFFFFF

    # 0x004d414d == "MAM" in little-endian (low 3 bytes)
    if magic != 0x004D414D:
        return None

    compressed = raw[8:]
    if crcck:
        if len(compressed) < 4:
            return None
        file_crc = struct.unpack_from("<I", compressed, 0)[0]
        crc = binascii.crc32(raw[:8])
        crc = binascii.crc32(struct.pack("<I", 0), crc)
        payload = compressed[4:]
        crc = binascii.crc32(payload, crc)
        if (crc & 0xFFFFFFFF) != file_crc:
            return None
        compressed = payload

    # Windows-only native decompression through ntdll.
    if platform.system().lower() != "windows":
        return None

    try:
        import ctypes

        try:
            ntdll = ctypes.windll.ntdll
        except Exception:
            ntdll = ctypes.CDLL("ntdll.dll")

        RtlDecompressBufferEx = ntdll.RtlDecompressBufferEx
        RtlGetCompressionWorkSpaceSize = ntdll.RtlGetCompressionWorkSpaceSize

        USHORT = ctypes.c_uint16
        ULONG = ctypes.c_uint32
        UCHAR = ctypes.c_ubyte

        workspace_size_buffer = ULONG()
        workspace_size_fragment = ULONG()

        ntstatus = RtlGetCompressionWorkSpaceSize(
            USHORT(calgo),
            ctypes.byref(workspace_size_buffer),
            ctypes.byref(workspace_size_fragment),
        )
        if ntstatus:
            return None

        compressed_size = len(compressed)
        nt_compressed = (UCHAR * compressed_size).from_buffer_copy(compressed)
        nt_decompressed = (UCHAR * decompressed_size)()
        nt_final_size = ULONG()
        nt_workspace = (UCHAR * workspace_size_fragment.value)()

        ntstatus = RtlDecompressBufferEx(
            USHORT(calgo),
            ctypes.byref(nt_decompressed),
            ULONG(decompressed_size),
            ctypes.byref(nt_compressed),
            ULONG(compressed_size),
            ctypes.byref(nt_final_size),
            ctypes.byref(nt_workspace),
        )
        if ntstatus:
            return None

        return bytes(bytearray(nt_decompressed))
    except Exception:
        return None


def _parse_scca_prefetch(data: bytes) -> Tuple[Optional[int], Optional[int], str, Optional[int], List[str]]:
    # Returns: (format_version, prefetch_hash, executable, run_count, last_run_times_utc)
    if len(data) < 0x54 + 4:
        raise ValueError("prefetch too small")

    format_version = struct.unpack_from("<I", data, 0)[0]
    if data[4:8] != b"SCCA":
        raise ValueError("missing SCCA signature")

    executable = _decode_utf16le_zstr(data[0x10 : 0x10 + 60])
    prefetch_hash = struct.unpack_from("<I", data, 0x4C)[0]

    file_info_base = 0x54
    run_count: Optional[int] = None
    last_runs: List[str] = []

    def read_filetime(off: int) -> Optional[str]:
        if off + 8 > len(data):
            return None
        ft = struct.unpack_from("<Q", data, off)[0]
        if ft == 0:
            return None
        try:
            return filetime_to_iso(int(ft))
        except Exception:
            return None

    if format_version == 17:
        lr = read_filetime(0x78)
        if lr:
            last_runs.append(lr)
        if 0x90 + 4 <= len(data):
            run_count = struct.unpack_from("<I", data, 0x90)[0]
    elif format_version == 23:
        lr = read_filetime(0x80)
        if lr:
            last_runs.append(lr)
        if 0x98 + 4 <= len(data):
            run_count = struct.unpack_from("<I", data, 0x98)[0]
    elif format_version == 26:
        # 8 run times: 1 most recent + 7 previous
        for i in range(8):
            lr = read_filetime(0x80 + (i * 8))
            if lr:
                last_runs.append(lr)
        if 0xD0 + 4 <= len(data):
            run_count = struct.unpack_from("<I", data, 0xD0)[0]
    elif format_version in (30, 31):
        # File information v30 has multiple variants; detect by file metrics array offset.
        file_metrics_offset = struct.unpack_from("<I", data, file_info_base + 0)[0]
        is_variant2 = file_metrics_offset == 0x128  # 296

        # last run times are at file_info + 44
        last_run_base = file_info_base + 44
        for i in range(8):
            lr = read_filetime(last_run_base + (i * 8))
            if lr:
                last_runs.append(lr)

        run_count_off = file_info_base + (116 if is_variant2 else 124)
        if run_count_off + 4 <= len(data):
            run_count = struct.unpack_from("<I", data, run_count_off)[0]
    else:
        # Unknown version: still return header fields.
        pass

    if not executable:
        executable = "UNKNOWN"

    return format_version, prefetch_hash, executable, run_count, last_runs


def parse_prefetch_file(pf_path: Path) -> PrefetchEntry:
    st = io.safe_stat(pf_path)
    if not st:
        raise ValueError("cannot stat prefetch file")

    raw = pf_path.read_bytes()
    data = raw
    if len(raw) >= 8 and raw[0:3] == b"MAM":
        decompressed = _maybe_decompress_mam(raw)
        if decompressed:
            data = decompressed

    format_version: Optional[int] = None
    prefetch_hash: Optional[int] = None
    executable = _parse_executable_from_pf_filename(pf_path)
    run_count: Optional[int] = None
    last_run_times: List[str] = []

    try:
        if len(data) >= 8 and data[4:8] == b"SCCA":
            format_version, prefetch_hash, executable, run_count, last_run_times = _parse_scca_prefetch(data)
    except Exception:
        # Keep minimal metadata-only parsing.
        pass

    return PrefetchEntry(
        pf_path=str(pf_path),
        executable=executable,
        format_version=format_version,
        prefetch_hash=prefetch_hash,
        run_count=run_count,
        last_run_times_utc=last_run_times,
        pf_mtime_utc=_utc_iso_from_stat_ts(st.st_mtime),
        pf_size=int(st.st_size),
    )


def collect_prefetch(
    *,
    prefetch_dir: Optional[Path] = None,
    max_entries: int = 200,
) -> Dict[str, Any]:
    pf_dir = prefetch_dir or default_prefetch_dir()
    result: Dict[str, Any] = {
        "enabled": True,
        "prefetch_dir": str(pf_dir),
        "entries": [],
        "entry_count": 0,
        "errors": [],
    }

    if platform.system().lower() != "windows":
        result["enabled"] = False
        result["errors"].append("Prefetch analizi sadece Windows üzerinde destekleniyor.")
        return result

    if not pf_dir.exists() or not pf_dir.is_dir():
        result["enabled"] = False
        result["errors"].append(f"Prefetch klasörü bulunamadı: {pf_dir}")
        return result

    entries: List[PrefetchEntry] = []
    for p in pf_dir.glob("*.pf"):
        try:
            entries.append(parse_prefetch_file(p))
        except Exception as e:
            result["errors"].append(f"{p.name}: {type(e).__name__}")

    def sort_key(e: PrefetchEntry) -> Tuple[int, str]:
        # Prefer most recent last_run; fallback to PF mtime.
        if e.last_run_times_utc:
            return (0, e.last_run_times_utc[0])
        return (1, e.pf_mtime_utc)

    entries_sorted = sorted(entries, key=sort_key, reverse=True)[:max_entries]
    result["entries"] = [asdict(e) for e in entries_sorted]
    result["entry_count"] = len(entries_sorted)
    return result

