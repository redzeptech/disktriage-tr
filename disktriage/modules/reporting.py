from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def render_text_report(payload: Dict[str, Any]) -> str:
    lines: List[str] = []
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

    prefetch_payload = payload.get("prefetch")
    if prefetch_payload is not None:
        prefetch_entries = prefetch_payload.get("entries") or []
        prefetch_dir = prefetch_payload.get("prefetch_dir") or ""
        prefetch_count = prefetch_payload.get("entry_count")
        prefetch_errors = prefetch_payload.get("errors") or []

        lines.append("Windows Prefetch (son çalıştırılan programlar):")
        if prefetch_dir:
            lines.append(f"  Klasör: {prefetch_dir}")
        if prefetch_count is not None:
            lines.append(f"  Kayıt:  {prefetch_count}")
        if prefetch_errors:
            lines.append("  Uyarılar:")
            for err in prefetch_errors[:5]:
                lines.append(f"    - {err}")

        if prefetch_entries:
            lines.append("")
            lines.append("  Top 20:")
            lines.append("    last_run_utc                  run_count  executable")
            lines.append("    ----------------------------  ---------  ------------------------------")
            for e in prefetch_entries[:20]:
                last_run = (e.get("last_run_times_utc") or [None])[0] or e.get("pf_mtime_utc") or ""
                run_count = e.get("run_count")
                run_count_s = str(run_count) if run_count is not None else "-"
                exe = e.get("executable") or ""
                lines.append(f"    {last_run[:28]:28}  {run_count_s:9}  {exe}")
        lines.append("")

    history_payload = payload.get("browser_history")
    if history_payload is not None:
        profiles = history_payload.get("profiles") or []
        errors = history_payload.get("errors") or []
        lines.append("Tarayıcı Geçmişi (Chrome/Edge/Firefox):")
        lines.append(f"  Profil: {history_payload.get('profile_count', 0)}")
        if errors:
            lines.append("  Uyarılar:")
            for err in errors[:5]:
                lines.append(f"    - {err}")
        if profiles:
            for p in profiles[:10]:
                browser = p.get("browser") or ""
                profile = p.get("profile") or ""
                item_count = p.get("item_count", 0)
                lines.append(f"  - {browser} / {profile} (Top {min(10, int(item_count) if item_count else 0)}):")
                for it in (p.get("items") or [])[:10]:
                    t = it.get("last_visit_utc") or ""
                    url = it.get("url") or ""
                    lines.append(f"      {t[:28]:28}  {url}")
        lines.append("")

    evtx_payload = payload.get("event_logs")
    if evtx_payload is not None:
        lines.append("Windows Event Log Özeti (EVTX / wevtutil):")
        lines.append(f"  Son gün: {evtx_payload.get('days', '-')}")
        errs = evtx_payload.get("errors") or []
        if errs:
            lines.append("  Uyarılar:")
            for err in errs[:5]:
                lines.append(f"    - {err}")

        sys_events = evtx_payload.get("system_critical_errors") or []
        lines.append(f"  System kritik/hata event sayısı: {len(sys_events)}")
        for e in sys_events[:10]:
            t = e.get("time_created_utc") or ""
            provider = e.get("provider") or ""
            event_id = e.get("event_id")
            lines.append(f"    {t[:28]:28}  {provider}  EventID={event_id}")

        sec = (evtx_payload.get("security_logons") or {}).get("summary") or {}
        if sec:
            lines.append("  Security logon özeti:")
            lines.append(f"    Başarılı: {sec.get('success_count', 0)}  Başarısız: {sec.get('failure_count', 0)}")
            top_users = sec.get("top_users") or []
            if top_users:
                lines.append("    Top kullanıcılar:")
                for u in top_users[:5]:
                    lines.append(f"      {u.get('count', 0):4}  {u.get('key','')}")
        lines.append("")

    ua_payload = payload.get("userassist")
    if ua_payload is not None:
        entries = ua_payload.get("entries") or []
        errs = ua_payload.get("errors") or []
        lines.append("UserAssist (HKCU) Özeti:")
        lines.append(f"  Kayıt: {ua_payload.get('entry_count', 0)}")
        if errs:
            lines.append("  Uyarılar:")
            for err in errs[:5]:
                lines.append(f"    - {err}")
        if entries:
            lines.append("  Top 20:")
            lines.append("    last_run_utc                  run_count  name")
            lines.append("    ----------------------------  ---------  ----------------------------------------")
            for e in entries[:20]:
                last_run = e.get("last_run_utc") or ""
                run_count = e.get("run_count")
                run_count_s = str(run_count) if run_count is not None else "-"
                name = e.get("name") or ""
                lines.append(f"    {last_run[:28]:28}  {run_count_s:9}  {name[:40]}")
        lines.append("")

    tl = payload.get("timeline") or {}
    if tl:
        lines.append("Zaman Tüneli (Timeline):")
        lines.append(f"  Toplam event: {tl.get('total_events', 0)}")
        by_source = tl.get("by_source") or {}
        if by_source:
            lines.append("  Kaynak dağılımı:")
            for k, v in list(by_source.items())[:10]:
                lines.append(f"    - {k}: {v}")
        lines.append("  CSV: reports/timeline.csv")
        lines.append("")

    pers = payload.get("persistence")
    if pers is not None:
        lines.append("Startup / Services / Scheduled Tasks (Persistence):")
        lines.append(f"  Run keys:         {len(pers.get('run_keys') or [])}")
        lines.append(f"  Startup klasörü:  {len(pers.get('startup_folder') or [])}")
        lines.append(f"  Servisler:        {len((pers.get('services') or {}).get('items') or [])}")
        lines.append(f"  Scheduled tasks:  {len(pers.get('scheduled_tasks') or [])}")
        lines.append(f"  Şüpheli:          {len(pers.get('suspicious') or [])}")
        lines.append(f"  İmza kontrolü:    {pers.get('signature_checks_performed', 0)}")
        sus = pers.get("suspicious") or []
        if sus:
            lines.append("  Top 15 şüpheli:")
            for f in sus[:15]:
                lines.append(f"    - [{f.get('kind')}] {f.get('name')} :: {f.get('exec_path') or ''}")
                rs = f.get("suspicious_reasons") or []
                if rs:
                    lines.append(f"      neden: {', '.join(rs[:6])}")
        lines.append("")

    vt = payload.get("virustotal")
    if vt is not None:
        lines.append("VirusTotal:")
        if not vt.get("enabled", True):
            lines.append("  Devre dışı: VT_API_KEY tanımlı değil veya erişilemedi.")
        else:
            lines.append(f"  Sorgulanan hash: {vt.get('checked', 0)}")
            reps = vt.get("reports") or []
            if reps:
                lines.append("  Top 10 sonuç:")
                lines.append("    malicious  suspicious  name")
                lines.append("    ---------  ----------  ------------------------------")
                for r in reps[:10]:
                    m = r.get("malicious")
                    s = r.get("suspicious")
                    n = r.get("meaningful_name") or r.get("sha256") or ""
                    lines.append(f"    {str(m) if m is not None else '-':9}  {str(s) if s is not None else '-':10}  {n[:30]}")
        errs = vt.get("errors") or []
        if errs:
            lines.append("  Uyarılar:")
            for e in errs[:3]:
                lines.append(f"    - {e}")
        lines.append("")

    lines.append("Not:")
    lines.append("  Bu çıktı eğitim ve farkındalık amaçlı adli ön inceleme raporudur.")
    lines.append("  Orijinal delilde değişiklik yapmamak için analizlerin imaj üzerinde yapılması önerilir.")
    lines.append("")

    return "\n".join(lines)


def write_text_report(out_path: Path, payload: Dict[str, Any]) -> None:
    out_path.write_text(render_text_report(payload), encoding="utf-8")


def write_json_report(out_path: Path, payload: Dict[str, Any]) -> None:
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

