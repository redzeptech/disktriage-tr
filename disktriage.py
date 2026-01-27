import argparse
import hashlib
import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, Dict, Any, List, Tuple

CHUNK_SIZE = 1024 * 1024  # 1MB


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_file(path: Path) -> Dict[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()

    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)

    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}


def safe_stat(p: Path) -> Optional[os.stat_result]:
    try:
        return p.stat()
    except Exception:
        return None


def to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


@dataclass
class FileRecord:
    path: str
    size: int
    mtime_utc: str
    ctime_utc: str


def iter_files(root: Path) -> Iterable[Path]:
    # root dosyaysa tek dosya; klasörse içini dolaş
    if root.is_file():
        yield root
        return

    for p in root.rglob("*"):
        if p.is_file():
            yield p


def build_inventory(root: Path, max_files: int = 200_000) -> List[FileRecord]:
    records: List[FileRecord] = []
    count = 0

    for p in iter_files(root):
        st = safe_stat(p)
        if not st:
            continue

        records.append(
            FileRecord(
                path=str(p.relative_to(root)) if root.is_dir() else str(p.name),
                size=int(st.st_size),
                mtime_utc=to_iso(st.st_mtime),
                ctime_utc=to_iso(st.st_ctime),
            )
        )

        count += 1
        if count >= max_files:
            break

    return records


def top_by_mtime(records: List[FileRecord], n: int = 50) -> List[FileRecord]:
    return sorted(records, key=lambda r: r.mtime_utc, reverse=True)[:n]


def summarize(records: List[FileRecord]) -> Dict[str, Any]:
    total_files = len(records)
    total_size = sum(r.size for r in records)
    biggest = sorted(records, key=lambda r: r.size, reverse=True)[:25]

    return {
        "total_files": total_files,
        "total_size_bytes": total_size,
        "biggest_files_top25": [asdict(x) for x in biggest],
        "recently_modified_top50": [asdict(x) for x in top_by_mtime(records, 50)],
    }


def write_text_report(out_path: Path, payload: Dict[str, Any]) -> None:
    lines = []
    lines.append("DiskTriage TR - Adli Ön İnceleme Raporu")
    lines.append(f"Tarih (UTC): {payload['created_utc']}")
    lines.append("")
    lines.append("Hedef:")
    lines.append(f"  Path: {payload['target']['path']}")
    lines.append(f"  Tip:  {payload['target']['type']}")
    lines.append("")
    if payload.get("target_hashes"):
        lines.append("Hash (Bütünlük):")
        lines.append(f"  SHA256: {payload['target_hashes']['sha256']}")
        lines.append(f"  MD5:    {payload['target_hashes']['md5']}")
        lines.append("")
    lines.append("Özet:")
    lines.append(f"  Toplam dosya: {payload['summary']['total_files']}")
    lines.append(f"  Toplam boyut (byte): {payload['summary']['total_size_bytes']}")
    lines.append("")
    lines.append("En büyük 10 dosya:")
    for r in payload["summary"]["biggest_files_top25"][:10]:
        lines.append(f"  {r['size']}  {r['path']}")
    lines.append("")
    lines.append("Son değişen 10 dosya (UTC):")
    for r in payload["summary"]["recently_modified_top50"][:10]:
        lines.append(f"  {r['mtime_utc']}  {r['path']}")
    lines.append("")
    lines.append("Not:")
    lines.append("  Bu çıktı eğitim ve farkındalık amaçlı adli ön inceleme raporudur.")
    lines.append("  Orijinal delilde değişiklik yapmamak için analizlerin imaj üzerinde yapılması önerilir.")
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="DiskTriage TR - Adli bilişim ön inceleme aracı (hash + envanter + timeline + rapor)."
    )
    ap.add_argument("target", help="İncelenecek hedef: klasör, dosya veya disk imajı (raw/dd).")
    ap.add_argument("--out", default=None, help="Çıktı klasörü. Verilmezse ./disktriage_out kullanılır.")
    ap.add_argument("--max-files", type=int, default=200_000, help="En fazla kaç dosya taransın.")
    ap.add_argument("--no-hash", action="store_true", help="Hedef dosya ise hash hesaplamayı atla.")
    args = ap.parse_args()

    target = Path(args.target).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve() if args.out else Path.cwd() / "disktriage_out"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not target.exists():
        raise SystemExit(f"Hedef bulunamadı: {target}")

    payload: Dict[str, Any] = {
        "created_utc": now_utc_iso(),
        "tool": {"name": "DiskTriage TR", "version": "1.0.0"},
        "target": {"path": str(target), "type": "file" if target.is_file() else "directory"},
        "target_hashes": None,
        "summary": {},
        "inventory_count": 0,
    }

    # Hash sadece hedef dosyaysa anlamlı (imaj dosyası gibi)
    if target.is_file() and not args.no_hash:
        payload["target_hashes"] = hash_file(target)

    # Envanter: hedef klasörse dosyaları tarar; hedef dosyaysa sadece dosyanın kendisini kaydeder
    if target.is_dir():
        records = build_inventory(target, max_files=args.max_files)
    else:
        st = safe_stat(target)
        records = []
        if st:
            records.append(
                FileRecord(
                    path=target.name,
                    size=int(st.st_size),
                    mtime_utc=to_iso(st.st_mtime),
                    ctime_utc=to_iso(st.st_ctime),
                )
            )

    payload["inventory_count"] = len(records)
    payload["summary"] = summarize(records)

    # JSON + TXT yaz
    json_path = out_dir / "report.json"
    txt_path = out_dir / "report.txt"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    write_text_report(txt_path, payload)

    print(f"Rapor üretildi: {txt_path}")
    print(f"JSON çıktı:    {json_path}")


if __name__ == "__main__":
    main()
