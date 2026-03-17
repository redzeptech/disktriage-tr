"""
Plotly tabanlı modern HTML rapor üretici.

Dosya Sistemi, Kayıt Defteri ve Sistem Logları verilerini alır;
Plotly grafikleri, DataTables.net tablosu ve karanlık mod tasarımı ile
reports/report_[timestamp].html olarak kaydeder.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .logging_utils import get_logger
from .timeline import collect_timeline_events, sort_events_desc

logger = get_logger("report_generator")

# Plotly dark theme
PLOTLY_LAYOUT = {
    "paper_bgcolor": "rgba(11, 18, 32, 1)",
    "plot_bgcolor": "rgba(17, 26, 46, 0.8)",
    "font": {"color": "#e5e7eb", "family": "ui-sans-serif, system-ui, sans-serif"},
    "xaxis": {
        "gridcolor": "rgba(255,255,255,0.06)",
        "zerolinecolor": "rgba(255,255,255,0.1)",
        "tickfont": {"color": "#9ca3af"},
    },
    "yaxis": {
        "gridcolor": "rgba(255,255,255,0.06)",
        "zerolinecolor": "rgba(255,255,255,0.1)",
        "tickfont": {"color": "#9ca3af"},
    },
    "legend": {"font": {"color": "#cbd5e1"}, "bgcolor": "rgba(0,0,0,0.2)"},
    "margin": {"t": 40, "b": 40, "l": 50, "r": 30},
    "height": 380,
}


def _extract_table_rows(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Tüm verileri DataTable için düz satır listesine dönüştürür."""
    rows: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Dosya Sistemi
    summary = payload.get("summary") or {}
    for r in (summary.get("biggest_files_top25") or [])[:50]:
        rows.append({
            "timestamp": r.get("mtime_utc") or r.get("ctime_utc") or now,
            "category": "Dosya Sistemi",
            "artifact_type": "Büyük dosya",
            "subject": r.get("path", ""),
            "details": f"Boyut: {r.get('size', 0)} byte",
        })
    for r in (summary.get("recently_modified_top50") or [])[:50]:
        rows.append({
            "timestamp": r.get("mtime_utc") or now,
            "category": "Dosya Sistemi",
            "artifact_type": "Son değişen",
            "subject": r.get("path", ""),
            "details": f"mtime: {r.get('mtime_utc', '')}",
        })
    pf = payload.get("prefetch") or {}
    for e in (pf.get("entries") or [])[:30]:
        ts = (e.get("last_run_times_utc") or [None])[0] or e.get("pf_mtime_utc") or now
        rows.append({
            "timestamp": ts,
            "category": "Dosya Sistemi",
            "artifact_type": "Prefetch",
            "subject": e.get("executable", ""),
            "details": f"Run count: {e.get('run_count', 0)}",
        })

    # Kayıt Defteri
    ua = payload.get("userassist") or {}
    for e in (ua.get("entries") or [])[:50]:
        rows.append({
            "timestamp": e.get("last_run_utc") or now,
            "category": "Kayıt Defteri",
            "artifact_type": "UserAssist",
            "subject": e.get("name", ""),
            "details": f"Run count: {e.get('run_count', 0)}",
        })
    pers = payload.get("persistence") or {}
    for r in (pers.get("run_keys") or [])[:20]:
        rows.append({
            "timestamp": r.get("timestamp_utc") or now,
            "category": "Kayıt Defteri",
            "artifact_type": "Run Key",
            "subject": r.get("name", ""),
            "details": (r.get("command") or r.get("value", ""))[:200],
        })
    for s in (pers.get("startup_folder") or [])[:20]:
        rows.append({
            "timestamp": s.get("timestamp_utc") or now,
            "category": "Kayıt Defteri",
            "artifact_type": "Startup",
            "subject": s.get("exec_path") or s.get("path", ""),
            "details": s.get("name", ""),
        })
    for s in (pers.get("suspicious") or [])[:30]:
        rows.append({
            "timestamp": now,
            "category": "Kayıt Defteri",
            "artifact_type": "Şüpheli",
            "subject": s.get("name", ""),
            "details": ", ".join(s.get("suspicious_reasons") or []),
        })

    # Sistem Logları
    evtx = payload.get("event_logs") or {}
    for e in (evtx.get("system_critical_errors") or [])[:50]:
        rows.append({
            "timestamp": e.get("time_created_utc") or now,
            "category": "Sistem Logları",
            "artifact_type": "EVTX System",
            "subject": e.get("provider", ""),
            "details": f"EventID: {e.get('event_id', '')}",
        })
    sec = (evtx.get("security_logons") or {}).get("events") or []
    for e in sec[:30]:
        rows.append({
            "timestamp": e.get("time_created_utc") or now,
            "category": "Sistem Logları",
            "artifact_type": "Security Logon",
            "subject": (e.get("data") or {}).get("TargetUserName", ""),
            "details": f"EventID: {e.get('event_id', '')}",
        })

    return rows


def _artifact_distribution(payload: Dict[str, Any]) -> Dict[str, int]:
    """Artifact türlerinin dağılımını hesaplar."""
    dist: Dict[str, int] = {}
    summary = payload.get("summary") or {}
    dist["Dosya (envanter)"] = summary.get("total_files", 0)
    dist["Prefetch"] = len((payload.get("prefetch") or {}).get("entries") or [])
    dist["UserAssist"] = len((payload.get("userassist") or {}).get("entries") or [])
    pers = payload.get("persistence") or {}
    dist["Run Keys"] = len(pers.get("run_keys") or [])
    dist["Startup"] = len(pers.get("startup_folder") or [])
    dist["Şüpheli"] = len(pers.get("suspicious") or [])
    evtx = payload.get("event_logs") or {}
    dist["EVTX System"] = len(evtx.get("system_critical_errors") or [])
    dist["EVTX Security"] = len((evtx.get("security_logons") or {}).get("events") or [])
    return {k: v for k, v in dist.items() if v > 0}


def _timeline_activity_data(payload: Dict[str, Any]) -> tuple[List[str], List[int]]:
    """Zaman bazlı aktivite yoğunluğu (günlük bucket)."""
    events = collect_timeline_events(payload)
    sorted_ev = sort_events_desc(events)
    buckets: Dict[str, int] = {}
    for e in sorted_ev:
        day = (e.timestamp_utc or "")[:10]
        if day:
            buckets[day] = buckets.get(day, 0) + 1
    days = sorted(buckets.keys())
    counts = [buckets[d] for d in days]
    return days, counts


def generate_report(
    *,
    dosya_sistemi: Optional[Dict[str, Any]] = None,
    kayit_defteri: Optional[Dict[str, Any]] = None,
    sistem_loglari: Optional[Dict[str, Any]] = None,
    payload: Optional[Dict[str, Any]] = None,
    out_dir: Path,
) -> Path:
    """
    Plotly + DataTables ile HTML rapor üretir.

    payload verilirse doğrudan kullanılır; aksi halde dosya_sistemi, kayit_defteri,
    sistem_loglari birleştirilerek payload oluşturulur.
    """
    try:
        import plotly.graph_objects as go
    except ImportError:
        logger.warning("Plotly yüklü değil; report_generator devre dışı.")
        raise ImportError("plotly paketi gerekli: pip install plotly") from None

    if payload is None:
        ds = dosya_sistemi or {}
        kd = kayit_defteri or {}
        sl = sistem_loglari or {}
        payload = {
            "summary": ds.get("summary", ds) if ds else {},
            "prefetch": ds.get("prefetch") if isinstance(ds, dict) else None,
            "userassist": kd.get("userassist", kd) if isinstance(kd, dict) else {},
            "persistence": kd.get("persistence", kd) if isinstance(kd, dict) else {},
            "event_logs": sl.get("event_logs", sl) if isinstance(sl, dict) else sl,
        }

    reports_dir = out_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    html_path = reports_dir / f"report_{ts}.html"

    # Tablo verisi
    table_rows = _extract_table_rows(payload)
    table_json = json.dumps(table_rows, ensure_ascii=False)

    # Grafik 1: Timeline (zaman bazlı aktivite)
    days, counts = _timeline_activity_data(payload)
    fig_timeline = go.Figure()
    if days and counts:
        fig_timeline.add_trace(
            go.Scatter(
                x=days,
                y=counts,
                mode="lines+markers",
                line=dict(color="#60a5fa", width=2),
                marker=dict(size=6),
                fill="tozeroy",
                fillcolor="rgba(96,165,250,0.2)",
            )
        )
    else:
        fig_timeline.add_annotation(
            text="Timeline verisi yok",
            xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
        )
    fig_timeline.update_layout(
        **PLOTLY_LAYOUT,
        title=dict(text="Zaman Bazlı Aktivite Yoğunluğu", font=dict(size=16)),
        xaxis_title="Tarih",
        yaxis_title="Olay sayısı",
    )
    timeline_html = fig_timeline.to_html(full_html=False, include_plotlyjs="cdn")

    # Grafik 2: Artifact dağılımı (Pie)
    dist = _artifact_distribution(payload)
    fig_pie = go.Figure()
    if dist:
        fig_pie.add_trace(
            go.Pie(
                labels=list(dist.keys()),
                values=list(dist.values()),
                hole=0.4,
                marker=dict(
                    colors=[
                        "#60a5fa", "#34d399", "#fbbf24", "#fb7185",
                        "#a78bfa", "#22c55e", "#f97316", "#ec4899",
                    ][: len(dist)],
                ),
                textinfo="label+percent",
            )
        )
    else:
        fig_pie.add_annotation(
            text="Artifact verisi yok",
            xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
        )
    pie_layout = {**PLOTLY_LAYOUT, "title": dict(text="Artifact Türü Dağılımı", font=dict(size=16))}
    pie_layout["legend"] = dict(orientation="h", yanchor="bottom", y=-0.2)
    fig_pie.update_layout(**pie_layout)
    pie_html = fig_pie.to_html(full_html=False, include_plotlyjs=False)

    html = f"""<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DiskTriage TR - Plotly Rapor</title>
  <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>
    :root {{
      --bg: #0b1220;
      --panel: #111a2e;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --accent: #60a5fa;
      --border: rgba(255,255,255,0.08);
    }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, sans-serif;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
    }}
    .table {{
      color: var(--text);
    }}
    .table thead th {{
      background: rgba(15,23,42,0.8);
      border-color: var(--border);
      color: #cbd5e1;
    }}
    .table td, .table th {{
      border-color: var(--border);
    }}
    .dataTables_wrapper .dataTables_filter input {{
      background: rgba(15,23,42,0.8);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 8px;
    }}
    .dataTables_wrapper .dataTables_length select {{
      background: rgba(15,23,42,0.8);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 6px;
    }}
    .dataTables_info, .dataTables_length label, .dataTables_filter label {{
      color: var(--muted) !important;
    }}
    .page-link {{
      background: var(--panel);
      border-color: var(--border);
      color: var(--accent);
    }}
    .page-link:hover {{
      background: rgba(96,165,250,0.15);
      border-color: var(--border);
      color: var(--accent);
    }}
    .page-item.active .page-link {{
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }}
    .page-item.disabled .page-link {{
      background: var(--panel);
      color: var(--muted);
    }}
  </style>
</head>
<body class="p-4">
  <div class="container-fluid">
    <header class="mb-4">
      <h1 class="h3">DiskTriage TR — Plotly Rapor</h1>
      <p class="text-muted">Üretim: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
    </header>

    <div class="row g-4 mb-4">
      <div class="col-12">
        <div class="card p-3">
          <h5 class="card-title">Zaman Bazlı Aktivite Yoğunluğu (Timeline)</h5>
          {timeline_html}
        </div>
      </div>
      <div class="col-12">
        <div class="card p-3">
          <h5 class="card-title">Artifact Türü Dağılımı (Pie Chart)</h5>
          {pie_html}
        </div>
      </div>
    </div>

    <div class="card p-3">
      <h5 class="card-title mb-3">Tüm Veriler — Filtrelenebilir Tablo</h5>
      <table id="dataTable" class="table table-dark table-striped table-hover" style="width:100%">
        <thead>
          <tr>
            <th>Zaman (UTC)</th>
            <th>Kategori</th>
            <th>Artifact Türü</th>
            <th>Konu</th>
            <th>Detay</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
  <script>
    const tableData = {table_json};
    $(document).ready(function() {{
      const table = $('#dataTable').DataTable({{
        data: tableData,
        columns: [
          {{ data: 'timestamp' }},
          {{ data: 'category' }},
          {{ data: 'artifact_type' }},
          {{ data: 'subject' }},
          {{ data: 'details' }}
        ],
        order: [[0, 'desc']],
        pageLength: 25,
        lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, 'Tümü']],
        language: {{
          search: 'Ara:',
          lengthMenu: '_MENU_ kayıt göster',
          info: '_TOTAL_ kayıttan _START_ - _END_ arası',
          infoEmpty: 'Kayıt yok',
          infoFiltered: '(_MAX_ kayıttan filtrelendi)',
          paginate: {{ first: 'İlk', last: 'Son', next: 'Sonraki', previous: 'Önceki' }}
        }}
      }});
    }});
  </script>
</body>
</html>
"""

    html_path.write_text(html, encoding="utf-8")
    logger.info("Plotly raporu kaydedildi: %s", html_path)
    return html_path
