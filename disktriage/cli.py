"""
Komut satırı arayüzü (CLI).

Argümanları okur, analiz adımlarını koordine eder ve rapor çıktılarını üretir.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .modules import (
    anonymizer,
    browser_history,
    console_output,
    evtx,
    html_report,
    io,
    persistence,
    prefetch,
    processing,
    report_generator,
    reporting,
    timeline,
    userassist,
    virustotal,
)
from .modules.logging_utils import configure_logging, get_logger
from .modules.utils import now_utc_iso

logger = get_logger("cli")


def _configure_utf8_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except Exception:
                pass


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="DiskTriage TR - Adli bilişim ön inceleme aracı (hash + envanter + timeline + rapor)."
    )
    ap.add_argument("target", help="İncelenecek hedef: klasör, dosya veya disk imajı (raw/dd).")
    ap.add_argument("--out", default=None, help="Çıktı klasörü. Verilmezse ./disktriage_out kullanılır.")
    ap.add_argument("--max-files", type=int, default=200_000, help="En fazla kaç dosya taransın.")
    ap.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Envanter taraması için thread sayısı (0/1: kapalı).",
    )
    ap.add_argument("--no-hash", action="store_true", help="Hedef dosya ise hash hesaplamayı atla.")
    ap.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log seviyesi (konsol + reports/disktriage.log).",
    )
    ap.add_argument(
        "--no-anonymize",
        action="store_true",
        help="Rapor çıktılarında kişisel veri maskelemesini kapat (varsayılan: açık).",
    )
    ap.add_argument(
        "--timeline",
        action="store_true",
        help="Tüm artifact verilerini birleştirip zaman tüneli (timeline) üret.",
    )
    ap.add_argument(
        "--timeline-embed-max",
        type=int,
        default=1000,
        help="JSON/HTML içine en fazla kaç timeline event gömülsün.",
    )
    ap.add_argument(
        "--timeline-csv-max",
        type=int,
        default=20000,
        help="CSV çıktısında en fazla kaç timeline event yazılsın.",
    )
    ap.add_argument(
        "--persistence",
        action="store_true",
        help="Startup (Run keys + Startup klasörü), servisler ve Scheduled Tasks listesini çıkar.",
    )
    ap.add_argument(
        "--persistence-new-service-days",
        type=int,
        default=7,
        help="Kaç gün içinde değişmiş/oluşmuş servisler şüpheli işaretlensin.",
    )
    ap.add_argument(
        "--sig-check-max",
        type=int,
        default=50,
        help="Şüpheli adaylarda yapılacak en fazla imza kontrolü (AuthentiCode).",
    )
    ap.add_argument(
        "--virustotal",
        action="store_true",
        help="Şüpheli çalıştırılabilirlerin SHA256 hashlerini hesapla ve VirusTotal ile kontrol et (VT_API_KEY gerekir).",
    )
    ap.add_argument(
        "--vt-max",
        type=int,
        default=25,
        help="VirusTotal'a en fazla kaç hash sorulsun.",
    )
    ap.add_argument(
        "--prefetch",
        action="store_true",
        help="Windows Prefetch (.pf) dosyalarından son çalıştırılan programları özetle.",
    )
    ap.add_argument(
        "--prefetch-dir",
        default=None,
        help=r"Prefetch klasörü (varsayılan: %%SystemRoot%%\Prefetch).",
    )
    ap.add_argument(
        "--prefetch-max",
        type=int,
        default=200,
        help="Prefetch tablosunda en fazla kaç kayıt gösterilsin.",
    )
    ap.add_argument(
        "--browser-history",
        action="store_true",
        help="Chrome/Edge/Firefox tarayıcı geçmişini (History/places.sqlite) özetle.",
    )
    ap.add_argument(
        "--history-max",
        type=int,
        default=50,
        help="Her profil için en fazla kaç geçmiş kaydı alınsın.",
    )
    ap.add_argument(
        "--evtx",
        action="store_true",
        help="Windows Event Log (System + Security) özetini ekle (wevtutil ile).",
    )
    ap.add_argument(
        "--evtx-days",
        type=int,
        default=7,
        help="Kaç günlük event log taransın.",
    )
    ap.add_argument(
        "--evtx-max",
        type=int,
        default=50,
        help="Her log için en fazla kaç event çekilsin.",
    )
    ap.add_argument(
        "--evtx-path",
        default=None,
        help="Canlı log yerine offline .evtx dosyası (wevtutil /lf:true). Not: Security bu modda devre dışı.",
    )
    ap.add_argument(
        "--userassist",
        action="store_true",
        help="HKCU UserAssist kayıtlarından son çalıştırılan program/öğe izlerini özetle.",
    )
    ap.add_argument(
        "--userassist-max",
        type=int,
        default=200,
        help="UserAssist tablosunda en fazla kaç kayıt gösterilsin.",
    )
    return ap


def build_payload(*, target: Path, no_hash: bool) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "created_utc": now_utc_iso(),
        "tool": {"name": "DiskTriage TR", "version": "1.0.0"},
        "target": {"path": str(target), "type": "file" if target.is_file() else "directory"},
        "target_hashes": None,
        "summary": {},
        "inventory_count": 0,
        "prefetch": None,
        "browser_history": None,
        "event_logs": None,
        "userassist": None,
        "persistence": None,
        "virustotal": None,
        "errors": [],
    }

    if target.is_file() and not no_hash:
        try:
            payload["target_hashes"] = io.hash_file(target)
        except Exception as e:
            logger.warning("Hash failed: %s", target, exc_info=True)
            payload["errors"].append(f"hash: {type(e).__name__}")

    return payload


def run(
    *,
    target: Path,
    out_dir: Path,
    max_files: int,
    workers: int,
    no_hash: bool,
    include_prefetch: bool,
    prefetch_dir: Optional[Path],
    prefetch_max: int,
    include_browser_history: bool,
    history_max: int,
    include_evtx: bool,
    evtx_days: int,
    evtx_max: int,
    evtx_path: Optional[str],
    include_userassist: bool,
    userassist_max: int,
    anonymize: bool,
    include_timeline: bool,
    timeline_embed_max: int,
    timeline_csv_max: int,
    include_persistence: bool,
    persistence_new_service_days: int,
    sig_check_max: int,
    include_virustotal: bool,
    vt_max: int,
) -> Tuple[Path, Path, Dict[str, Any]]:
    if not target.exists():
        raise FileNotFoundError(f"Hedef bulunamadı: {target}")

    out_dir.mkdir(parents=True, exist_ok=True)

    payload = build_payload(target=target, no_hash=no_hash)
    try:
        records = processing.build_inventory(target, max_files=max_files, workers=workers)
    except Exception as e:
        logger.exception("Inventory failed")
        payload["errors"].append(f"inventory: {type(e).__name__}")
        records = []
    payload["inventory_count"] = len(records)
    payload["summary"] = processing.summarize(records)

    if include_prefetch:
        try:
            payload["prefetch"] = prefetch.collect_prefetch(prefetch_dir=prefetch_dir, max_entries=prefetch_max)
        except Exception as e:
            logger.exception("Prefetch collection failed")
            payload["errors"].append(f"prefetch: {type(e).__name__}")

    if include_browser_history:
        try:
            payload["browser_history"] = browser_history.collect_browser_history(max_items_per_profile=history_max)
        except Exception as e:
            logger.exception("Browser history collection failed")
            payload["errors"].append(f"browser_history: {type(e).__name__}")

    if include_evtx:
        try:
            payload["event_logs"] = evtx.collect_event_logs(
                days=evtx_days,
                max_events=evtx_max,
                include_security=True,
                evtx_path=evtx_path,
            )
        except Exception as e:
            logger.exception("EVTX collection failed")
            payload["errors"].append(f"evtx: {type(e).__name__}")

    if include_userassist:
        try:
            payload["userassist"] = userassist.collect_userassist(max_entries=userassist_max)
        except Exception as e:
            logger.exception("UserAssist collection failed")
            payload["errors"].append(f"userassist: {type(e).__name__}")

    if include_persistence:
        try:
            payload["persistence"] = persistence.collect_persistence(
                new_service_days=int(persistence_new_service_days),
                sig_check_max=int(sig_check_max),
            )
        except Exception as e:
            logger.exception("Persistence collection failed")
            payload["errors"].append(f"persistence: {type(e).__name__}")

    if include_virustotal:
        try:
            paths: List[str] = []
            pers = payload.get("persistence") or {}
            for f in (pers.get("suspicious") or []):
                p = f.get("exec_path")
                if isinstance(p, str) and p:
                    paths.append(p)

            hashes: List[str] = []
            seen_paths = set()
            for p in paths:
                try:
                    if p.lower() in seen_paths:
                        continue
                    seen_paths.add(p.lower())
                    pp = Path(p)
                    if not pp.exists() or not pp.is_file():
                        continue
                    if pp.suffix.lower() not in (".exe", ".dll", ".sys"):
                        continue
                    h = io.hash_file(pp).get("sha256")
                    if h:
                        hashes.append(h)
                except Exception:
                    logger.debug("VT hash failed: %s", p, exc_info=True)

            payload["virustotal"] = virustotal.check_hashes(hashes, max_items=int(vt_max))
        except Exception as e:
            logger.exception("VirusTotal step failed")
            payload["errors"].append(f"virustotal: {type(e).__name__}")

    json_path = out_dir / "report.json"
    txt_path = out_dir / "report.txt"
    out_payload = anonymizer.anonymize_payload(payload) if anonymize else payload
    if include_timeline:
        try:
            out_payload["timeline"] = timeline.build_timeline(out_payload, embed_max=timeline_embed_max)
        except Exception as e:
            logger.exception("Timeline build failed")
            out_payload.setdefault("errors", []).append(f"timeline: {type(e).__name__}")

    reporting.write_json_report(json_path, out_payload)
    reporting.write_text_report(txt_path, out_payload)
    html_report.write_interactive_html_report(out_dir=out_dir, payload=out_payload)
    try:
        report_generator.generate_report(payload=out_payload, out_dir=out_dir)
    except ImportError:
        pass

    if include_timeline:
        try:
            ev = timeline.collect_timeline_events(out_payload)
            ev_sorted = timeline.sort_events_desc(ev)
            timeline.write_timeline_csv(out_dir / "reports" / "timeline.csv", ev_sorted[: int(timeline_csv_max)])
        except Exception as e:
            logger.exception("Timeline CSV failed")
            out_payload.setdefault("errors", []).append(f"timeline_csv: {type(e).__name__}")

    return txt_path, json_path, out_payload


def main(argv: Optional[Sequence[str]] = None) -> int:
    _configure_utf8_console()
    ap = build_arg_parser()
    args = ap.parse_args(argv)

    target = Path(args.target).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve() if args.out else Path.cwd() / "disktriage_out"

    pf_dir = Path(args.prefetch_dir).expanduser().resolve() if args.prefetch_dir else None
    configure_logging(out_dir=out_dir, level=str(args.log_level))
    logger.info("Run started. target=%s out_dir=%s", target, out_dir)

    try:
        txt_path, json_path, payload = run(
            target=target,
            out_dir=out_dir,
            max_files=int(args.max_files),
            workers=int(args.workers),
            no_hash=bool(args.no_hash),
            include_prefetch=bool(args.prefetch),
            prefetch_dir=pf_dir,
            prefetch_max=int(args.prefetch_max),
            include_browser_history=bool(args.browser_history),
            history_max=int(args.history_max),
            include_evtx=bool(args.evtx),
            evtx_days=int(args.evtx_days),
            evtx_max=int(args.evtx_max),
            evtx_path=str(args.evtx_path) if args.evtx_path else None,
            include_userassist=bool(args.userassist),
            userassist_max=int(args.userassist_max),
            anonymize=not bool(args.no_anonymize),
            include_timeline=bool(args.timeline),
            timeline_embed_max=int(args.timeline_embed_max),
            timeline_csv_max=int(args.timeline_csv_max),
            include_persistence=bool(args.persistence),
            persistence_new_service_days=int(args.persistence_new_service_days),
            sig_check_max=int(args.sig_check_max),
            include_virustotal=bool(args.virustotal),
            vt_max=int(args.vt_max),
        )
    except FileNotFoundError as e:
        logger.error("%s", e)
        print(str(e), file=sys.stderr)
        return 2
    except Exception as e:
        logger.exception("Unhandled error")
        print(f"Hata: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    console_output.print_run_summary(payload=payload, txt_path=txt_path, json_path=json_path, out_dir=out_dir)
    logger.info("Run finished successfully.")
    return 0
