from __future__ import annotations

"""
Veri işleme (processing) katmanı.

Bu modül dosya envanterini çıkarır, temel istatistikleri üretir ve raporlama
katmanına verilecek özet veri yapısını hazırlar.
"""

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import io
from .logging_utils import get_logger
from .models import FileRecord
from .utils import to_iso

logger = get_logger("processing")


def _make_record(p: Path, root: Path) -> Optional[FileRecord]:
    st = io.safe_stat(p)
    if not st:
        return None
    try:
        rel = str(p.relative_to(root)) if root.is_dir() else str(p.name)
    except Exception:
        rel = str(p)
    return FileRecord(
        path=rel,
        size=int(st.st_size),
        mtime_utc=to_iso(st.st_mtime),
        ctime_utc=to_iso(st.st_ctime),
    )


def build_inventory(
    root: Path,
    *,
    max_files: int = 200_000,
    workers: int = 0,
    buffer_size: int = 2000,
) -> List[FileRecord]:
    records: List[FileRecord] = []
    submitted = 0

    logger.info("Building inventory. root=%s max_files=%s workers=%s", root, max_files, workers)

    if workers and workers > 1:
        futures: List[Future[Optional[FileRecord]]] = []
        with ThreadPoolExecutor(max_workers=int(workers)) as ex:
            for p in io.iter_files(root):
                futures.append(ex.submit(_make_record, p, root))
                submitted += 1

                if submitted % 10000 == 0:
                    logger.info("Inventory progress: submitted=%s records=%s", submitted, len(records))

                if len(futures) >= buffer_size:
                    drain = futures[: buffer_size // 2]
                    futures = futures[buffer_size // 2 :]
                    for f in drain:
                        rec = f.result()
                        if rec:
                            records.append(rec)
                        if len(records) >= max_files:
                            break

                if submitted >= max_files:
                    break

            for f in futures:
                rec = f.result()
                if rec:
                    records.append(rec)
                if len(records) >= max_files:
                    break
    else:
        for p in io.iter_files(root):
            rec = _make_record(p, root)
            submitted += 1
            if rec:
                records.append(rec)
            if submitted % 10000 == 0:
                logger.info("Inventory progress: scanned=%s records=%s", submitted, len(records))
            if submitted >= max_files:
                break

    logger.info("Inventory done. scanned=%s records=%s", submitted, len(records))
    return records


def top_by_mtime(records: List[FileRecord], n: int = 50) -> List[FileRecord]:
    return sorted(records, key=lambda r: r.mtime_utc, reverse=True)[:n]


def _extension_counts(records: List[FileRecord], top_n: int = 15) -> List[Dict[str, Any]]:
    """Dosya uzantısı bazlı sayım; pasta grafiği için."""
    from collections import Counter

    exts: List[str] = []
    for r in records:
        p = r.path
        if "." in p and not p.endswith("."):
            ext = "." + p.rsplit(".", 1)[-1].lower()
            if len(ext) <= 12:
                exts.append(ext)
    cnt = Counter(exts)
    return [{"ext": k, "count": v} for k, v in cnt.most_common(top_n)]


def summarize(records: List[FileRecord]) -> Dict[str, Any]:
    total_files = len(records)

    if total_files >= 80_000:
        try:
            import pandas as pd  # type: ignore

            df = pd.DataFrame(
                {
                    "path": [r.path for r in records],
                    "size": [r.size for r in records],
                    "mtime_utc": [r.mtime_utc for r in records],
                    "ctime_utc": [r.ctime_utc for r in records],
                }
            )

            total_size = int(df["size"].sum())
            biggest_df = df.nlargest(25, "size")
            recent_df = df.sort_values("mtime_utc", ascending=False).head(50)

            ext_counts = _extension_counts(records, 15)

            return {
                "total_files": total_files,
                "total_size_bytes": total_size,
                "biggest_files_top25": biggest_df.to_dict(orient="records"),
                "recently_modified_top50": recent_df.to_dict(orient="records"),
                "extension_counts": ext_counts,
                "engine": "pandas",
            }
        except Exception:
            logger.debug("pandas summarize failed; falling back", exc_info=True)

    total_size = sum(r.size for r in records)
    biggest = sorted(records, key=lambda r: r.size, reverse=True)[:25]
    ext_counts = _extension_counts(records, 15)

    return {
        "total_files": total_files,
        "total_size_bytes": total_size,
        "biggest_files_top25": [asdict(x) for x in biggest],
        "recently_modified_top50": [asdict(x) for x in top_by_mtime(records, 50)],
        "extension_counts": ext_counts,
        "engine": "python",
    }

