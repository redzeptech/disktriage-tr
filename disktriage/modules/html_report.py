from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


def _safe_json_for_script(payload: Dict[str, Any]) -> str:
    # Prevent closing script tag injection issues.
    s = json.dumps(payload, ensure_ascii=False)
    return s.replace("</script>", "<\\/script>")


def write_interactive_html_report(
    *,
    out_dir: Path,
    payload: Dict[str, Any],
    filename: str = "report.html",
) -> Tuple[Path, Path]:
    """
    Writes an interactive HTML report with charts into: out_dir / "reports" / filename
    and also writes a JSON copy into: out_dir / "reports" / "report.json"
    """
    reports_dir = out_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    html_path = reports_dir / filename
    json_path = reports_dir / "report.json"

    payload_json = _safe_json_for_script(payload)

    html = f"""<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DiskTriage TR - Rapor</title>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: #111a2e;
      --panel2: #0f172a;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --accent: #60a5fa;
      --border: rgba(255,255,255,0.08);
      --good: #34d399;
      --warn: #fbbf24;
      --bad: #fb7185;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, "Helvetica Neue", Arial, "Noto Sans", "Liberation Sans";
      background: radial-gradient(1200px 600px at 10% 0%, rgba(96,165,250,0.12), transparent 60%),
                  radial-gradient(900px 500px at 90% 20%, rgba(52,211,153,0.10), transparent 55%),
                  var(--bg);
      color: var(--text);
    }}
    .wrap {{ max-width: 1120px; margin: 0 auto; padding: 28px 18px 40px; }}
    header {{
      display: flex; flex-wrap: wrap; gap: 14px;
      align-items: baseline; justify-content: space-between;
      padding: 16px 16px; background: rgba(17,26,46,0.62);
      border: 1px solid var(--border); border-radius: 14px;
      backdrop-filter: blur(8px);
    }}
    header .title {{ font-weight: 700; letter-spacing: 0.2px; }}
    header .sub {{ color: var(--muted); font-size: 13px; }}
    .grid {{ display: grid; gap: 14px; margin-top: 14px; }}
    @media (min-width: 860px) {{ .grid.cols-3 {{ grid-template-columns: repeat(3, 1fr); }} }}
    @media (min-width: 860px) {{ .grid.cols-2 {{ grid-template-columns: repeat(2, 1fr); }} }}
    .card {{
      background: rgba(17,26,46,0.60);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 14px 14px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.20);
    }}
    .card h3 {{ margin: 0 0 8px; font-size: 14px; color: #cbd5e1; font-weight: 650; }}
    .kpi {{ font-size: 22px; font-weight: 750; }}
    .muted {{ color: var(--muted); font-size: 12.5px; }}
    .row {{ display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }}
    .pill {{
      padding: 6px 10px; border-radius: 999px;
      border: 1px solid var(--border); background: rgba(15,23,42,0.70);
      color: #cbd5e1; font-size: 12px;
    }}
    .pill.good {{ border-color: rgba(52,211,153,0.35); }}
    .pill.warn {{ border-color: rgba(251,191,36,0.35); }}
    .pill.bad {{ border-color: rgba(251,113,133,0.35); }}
    canvas {{ width: 100% !important; height: 320px !important; }}
    .table {{
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
      border-radius: 12px;
      border: 1px solid var(--border);
    }}
    .table th, .table td {{
      padding: 9px 10px;
      border-bottom: 1px solid rgba(255,255,255,0.06);
      vertical-align: top;
      font-size: 13px;
    }}
    .table th {{ text-align: left; color: #cbd5e1; background: rgba(15,23,42,0.65); }}
    .table tr:hover td {{ background: rgba(96,165,250,0.06); }}
    .table tr.row-bad td {{ background: rgba(251,113,133,0.11); }}
    .table tr.row-warn td {{ background: rgba(251,191,36,0.09); }}
    .note {{
      margin-top: 14px;
      color: var(--muted);
      font-size: 12.5px;
      line-height: 1.5;
    }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .footer {{ margin-top: 16px; color: var(--muted); font-size: 12px; }}
    .controls {{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }}
    input[type="search"] {{
      background: rgba(15,23,42,0.70);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 10px;
      padding: 8px 10px;
      min-width: 260px;
      outline: none;
    }}
  </style>
  <script id="payload" type="application/json">{payload_json}</script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>
</head>
<body>
  <div class="wrap">
    <header>
      <div>
        <div class="title">DiskTriage TR — İnteraktif Rapor</div>
        <div class="sub" id="subtitle"></div>
      </div>
      <div class="row">
        <div class="pill" id="targetType"></div>
        <div class="pill" id="inventoryCount"></div>
      </div>
    </header>

    <div class="grid cols-3">
      <div class="card">
        <h3>Toplam dosya</h3>
        <div class="kpi" id="kTotalFiles">-</div>
        <div class="muted">Envanter taraması</div>
      </div>
      <div class="card">
        <h3>Toplam boyut</h3>
        <div class="kpi" id="kTotalSize">-</div>
        <div class="muted">Byte cinsinden</div>
      </div>
      <div class="card">
        <h3>Rapor çıktıları</h3>
        <div class="muted">Bu HTML: <code>reports/{filename}</code></div>
        <div class="muted">JSON kopya: <code>reports/report.json</code></div>
      </div>
    </div>

    <div class="card" style="margin-top:14px;">
      <h3>Hata / Uyarı Özeti — Kritik Bulgular</h3>
      <div class="row" id="alertDashboard">
        <div class="pill" id="alertErrors">Hatalar: 0</div>
        <div class="pill" id="alertSuspicious">Şüpheli: 0</div>
        <div class="pill" id="alertVTMalicious">VT Malicious: 0</div>
        <div class="pill" id="alertVTSuspicious">VT Suspicious: 0</div>
      </div>
      <div class="muted" id="alertHint">Tüm kritik bulgular burada özetlenir.</div>
    </div>

    <div class="grid cols-2">
      <div class="card">
        <h3>En büyük dosyalar (Top 10)</h3>
        <canvas id="chartBiggest"></canvas>
      </div>
      <div class="card">
        <h3>Son değişen dosyalar (Top 10)</h3>
        <canvas id="chartRecent"></canvas>
      </div>
    </div>

    <div class="card">
      <h3>Dosya Türü Dağılımı</h3>
      <canvas id="chartFileTypes"></canvas>
      <div class="muted" id="fileTypeHint">exe, pdf, lnk vb. uzantı bazlı yoğunluk</div>
    </div>

    <div class="grid cols-2">
      <div class="card">
        <h3>Windows Prefetch</h3>
        <div class="row" style="margin-bottom:10px;">
          <div class="pill" id="pfPill"></div>
          <div class="pill" id="pfDirPill"></div>
        </div>
        <canvas id="chartPrefetch"></canvas>
        <div class="muted" id="pfHint"></div>
      </div>
      <div class="card">
        <h3>Tarayıcı Geçmişi</h3>
        <canvas id="chartHistory"></canvas>
        <div class="muted" id="historyHint"></div>
      </div>
    </div>

    <div class="grid cols-2">
      <div class="card">
        <h3>Event Log — System (Critical/Error)</h3>
        <canvas id="chartEvtxProviders"></canvas>
        <div class="muted" id="evtxHint"></div>
      </div>
      <div class="card">
        <h3>UserAssist</h3>
        <canvas id="chartUserAssist"></canvas>
        <div class="muted" id="uaHint"></div>
        <div class="note" style="margin-top:10px;">
          UserAssist verisi kullanıcı bazlıdır ve HKCU üzerinden okunur.
        </div>
      </div>
    </div>

    <div class="grid cols-2">
      <div class="card">
        <h3>Hızlı arama</h3>
        <div class="controls">
          <input id="q" type="search" placeholder="URL / dosya / executable ara..." />
          <span class="muted">Sonuçlar aşağıdaki tablolarda filtrelenir.</span>
        </div>
        <div class="note">
          Chart.js CDN ile yüklenir. Offline ortamda grafikler görünmeyebilir; ancak tablolar ve JSON veri yine de kullanılabilir.
        </div>
      </div>
      <div class="card">
        <h3>UserAssist (Top 20)</h3>
        <table class="table" id="tblUserAssist"></table>
      </div>
    </div>

    <div class="grid cols-2">
      <div class="card">
        <h3>Zaman Tüneli (Timeline)</h3>
        <canvas id="chartTimeline"></canvas>
        <div class="muted" id="tlHint"></div>
        <div class="note" style="margin-top:10px;">
          CSV: <code>reports/timeline.csv</code>
        </div>
      </div>
      <div class="card">
        <h3>Timeline (Top 50)</h3>
        <table class="table" id="tblTimeline"></table>
      </div>
    </div>

    <div class="grid cols-2">
      <div class="card">
        <h3>Persistence (Startup/Services/Tasks)</h3>
        <canvas id="chartPersistence"></canvas>
        <div class="muted" id="persHint"></div>
      </div>
      <div class="card">
        <h3>Şüpheli bulgular (Top 30)</h3>
        <table class="table" id="tblPersistence"></table>
      </div>
    </div>

    <div class="grid cols-2">
      <div class="card">
        <h3>VirusTotal (Top 10)</h3>
        <canvas id="chartVT"></canvas>
        <div class="muted" id="vtHint"></div>
      </div>
      <div class="card">
        <h3>VirusTotal sonuçları</h3>
        <table class="table" id="tblVT"></table>
      </div>
    </div>

    <div class="grid cols-2">
      <div class="card">
        <h3>En büyük dosyalar (Top 25)</h3>
        <table class="table" id="tblBiggest"></table>
      </div>
      <div class="card">
        <h3>Tarayıcı geçmişi (Top 10 / profil)</h3>
        <table class="table" id="tblHistory"></table>
      </div>
    </div>

    <div class="grid cols-2">
      <div class="card">
        <h3>Prefetch (Top 20)</h3>
        <table class="table" id="tblPrefetch"></table>
      </div>
      <div class="card">
        <h3>Event Log — System (Top 10)</h3>
        <table class="table" id="tblEvtx"></table>
      </div>
    </div>

    <div class="footer">
      <div>Üretim zamanı (UTC): <span id="createdUtc"></span></div>
      <div class="note">
        Bu çıktı eğitim ve farkındalık amaçlıdır. Gerçek adli süreçlerde uygun usuller ve araçlar kullanılmalıdır.
      </div>
    </div>
  </div>

  <script>
    const payload = JSON.parse(document.getElementById('payload').textContent);

    const created = payload.created_utc || '';
    document.getElementById('createdUtc').textContent = created;
    document.getElementById('subtitle').textContent =
      (payload.tool?.name || 'DiskTriage') + ' v' + (payload.tool?.version || '') + ' • ' + created;

    document.getElementById('targetType').textContent = 'Target: ' + (payload.target?.type || '-');
    document.getElementById('inventoryCount').textContent = 'Inventory: ' + String(payload.inventory_count ?? 0);
    document.getElementById('kTotalFiles').textContent = String(payload.summary?.total_files ?? '-');
    document.getElementById('kTotalSize').textContent = String(payload.summary?.total_size_bytes ?? '-');

    // Hata/Uyarı Özeti — Kritik Bulgular
    const errors = payload.errors || [];
    const persSus = (payload.persistence?.suspicious || []).length;
    const vtReports = payload.virustotal?.reports || [];
    const vtMal = vtReports.filter(r => (r.malicious || 0) > 0).length;
    const vtSusp = vtReports.filter(r => (r.suspicious || 0) > 0 && (r.malicious || 0) === 0).length;

    const errEl = document.getElementById('alertErrors');
    const susEl = document.getElementById('alertSuspicious');
    const vtMalEl = document.getElementById('alertVTMalicious');
    const vtSuspEl = document.getElementById('alertVTSuspicious');
    errEl.textContent = 'Hatalar: ' + errors.length;
    if (errors.length > 0) errEl.classList.add('bad');
    susEl.textContent = 'Şüpheli: ' + persSus;
    if (persSus > 0) susEl.classList.add('warn');
    vtMalEl.textContent = 'VT Malicious: ' + vtMal;
    if (vtMal > 0) vtMalEl.classList.add('bad');
    vtSuspEl.textContent = 'VT Suspicious: ' + vtSusp;
    if (vtSusp > 0) vtSuspEl.classList.add('warn');

    const alertHint = document.getElementById('alertHint');
    const hasAlerts = errors.length > 0 || persSus > 0 || vtMal > 0 || vtSusp > 0;
    alertHint.textContent = hasAlerts ? 'Kritik bulgular tespit edildi — detaylar için aşağıdaki tablolara bakın.' : 'Kritik bulgu yok.';

    function topN(arr, n) {{
      return (arr || []).slice(0, n);
    }}

    function fmtShort(s, max=88) {{
      if (!s) return '';
      return s.length > max ? (s.slice(0, max-1) + '…') : s;
    }}

    function providerCounts(events) {{
      const d = new Map();
      for (const e of (events || [])) {{
        const k = e.provider || '(unknown)';
        d.set(k, (d.get(k) || 0) + 1);
      }}
      const rows = [...d.entries()].sort((a,b)=>b[1]-a[1]).slice(0, 10);
      return {{
        labels: rows.map(r => r[0]),
        data: rows.map(r => r[1]),
      }};
    }}

    function buildTable(el, headers, rows) {{
      el.innerHTML = '';
      const thead = document.createElement('thead');
      const trh = document.createElement('tr');
      for (const h of headers) {{
        const th = document.createElement('th'); th.textContent = h;
        trh.appendChild(th);
      }}
      thead.appendChild(trh);
      const tbody = document.createElement('tbody');
      for (const r of rows) {{
        const tr = document.createElement('tr');
        for (const c of r) {{
          const td = document.createElement('td');
          if (c && c.__html) td.innerHTML = c.__html;
          else td.textContent = c == null ? '' : String(c);
          tr.appendChild(td);
        }}
        tbody.appendChild(tr);
      }}
      el.appendChild(thead);
      el.appendChild(tbody);
    }}

    // Biggest files chart + table
    const biggest = topN(payload.summary?.biggest_files_top25, 10);
    new Chart(document.getElementById('chartBiggest'), {{
      type: 'bar',
      data: {{
        labels: biggest.map(x => fmtShort(x.path, 26)),
        datasets: [{{
          label: 'Size (bytes)',
          data: biggest.map(x => x.size || 0),
          backgroundColor: 'rgba(96,165,250,0.55)',
          borderColor: 'rgba(96,165,250,0.95)',
          borderWidth: 1
        }}]
      }},
      options: {{
        responsive: true,
        plugins: {{
          legend: {{ display: false }},
          tooltip: {{
            callbacks: {{
              title: (items) => biggest[items[0].dataIndex]?.path || ''
            }}
          }}
        }},
        scales: {{
          x: {{ ticks: {{ color: '#cbd5e1' }} }},
          y: {{ ticks: {{ color: '#cbd5e1' }} }}
        }}
      }}
    }});

    buildTable(
      document.getElementById('tblBiggest'),
      ['Size', 'Path'],
      (payload.summary?.biggest_files_top25 || []).slice(0, 25).map(x => [x.size, x.path])
    );

    // Dosya Türü Dağılımı (pasta)
    const extCounts = payload.summary?.extension_counts || [];
    const pieColors = [
      'rgba(96,165,250,0.75)', 'rgba(52,211,153,0.75)', 'rgba(251,191,36,0.75)',
      'rgba(251,113,133,0.75)', 'rgba(167,139,250,0.75)', 'rgba(34,197,94,0.75)',
      'rgba(249,115,22,0.75)', 'rgba(236,72,153,0.75)', 'rgba(14,165,233,0.75)',
      'rgba(132,204,22,0.75)', 'rgba(234,88,12,0.75)', 'rgba(168,85,247,0.75)',
      'rgba(20,184,166,0.75)', 'rgba(244,63,94,0.75)', 'rgba(250,204,21,0.75)'
    ];
    new Chart(document.getElementById('chartFileTypes'), {{
      type: 'doughnut',
      data: {{
        labels: extCounts.map(x => (x.ext || '') + ' (' + (x.count || 0) + ')'),
        datasets: [{{
          data: extCounts.map(x => x.count || 0),
          backgroundColor: pieColors.slice(0, extCounts.length),
          borderWidth: 1,
        }}]
      }},
      options: {{
        responsive: true,
        plugins: {{
          legend: {{ labels: {{ color: '#cbd5e1' }}, position: 'right' }},
          tooltip: {{
            callbacks: {{
              label: (ctx) => {{
                const tot = ctx.dataset.data.reduce((a,b)=>a+b, 0);
                const pct = tot ? ((ctx.raw / tot) * 100).toFixed(1) : 0;
                return ctx.label + ' — ' + pct + '%';
              }}
            }}
          }}
        }}
      }}
    }});

    // Recent modified chart
    const recent = topN(payload.summary?.recently_modified_top50, 10);
    new Chart(document.getElementById('chartRecent'), {{
      type: 'line',
      data: {{
        labels: recent.map(x => fmtShort(x.path, 24)),
        datasets: [{{
          label: 'mtime (UTC)',
          data: recent.map(x => Date.parse(x.mtime_utc || 0)),
          borderColor: 'rgba(52,211,153,0.9)',
          backgroundColor: 'rgba(52,211,153,0.25)',
          tension: 0.25,
          pointRadius: 2,
        }}]
      }},
      options: {{
        plugins: {{
          legend: {{ display: false }},
          tooltip: {{
            callbacks: {{
              label: (ctx) => {{
                const idx = ctx.dataIndex;
                return recent[idx]?.mtime_utc || '';
              }},
              title: (items) => recent[items[0].dataIndex]?.path || ''
            }}
          }}
        }},
        scales: {{
          x: {{ ticks: {{ color: '#cbd5e1' }} }},
          y: {{
            ticks: {{
              color: '#cbd5e1',
              callback: (v) => (new Date(v)).toISOString().replace('T',' ').slice(0,19) + 'Z'
            }}
          }}
        }}
      }}
    }});

    // Prefetch chart + table
    const pf = payload.prefetch;
    const pfEntries = pf?.entries || [];
    document.getElementById('pfPill').textContent = 'Kayıt: ' + String(pf?.entry_count ?? 0);
    document.getElementById('pfDirPill').textContent = 'Klasör: ' + String(pf?.prefetch_dir ?? '-');
    document.getElementById('pfHint').textContent = (pf?.errors && pf.errors.length) ? ('Uyarı: ' + pf.errors[0]) : '';

    const pfTop = pfEntries.slice(0, 10);
    new Chart(document.getElementById('chartPrefetch'), {{
      type: 'bar',
      data: {{
        labels: pfTop.map(x => fmtShort(x.executable, 26)),
        datasets: [{{
          label: 'Run count',
          data: pfTop.map(x => (x.run_count == null ? 0 : x.run_count)),
          backgroundColor: 'rgba(251,191,36,0.5)',
          borderColor: 'rgba(251,191,36,0.95)',
          borderWidth: 1
        }}]
      }},
      options: {{
        plugins: {{
          legend: {{ display: false }},
          tooltip: {{
            callbacks: {{
              title: (items) => pfTop[items[0].dataIndex]?.executable || ''
            }}
          }}
        }},
        scales: {{
          x: {{ ticks: {{ color: '#cbd5e1' }} }},
          y: {{ ticks: {{ color: '#cbd5e1' }} }}
        }}
      }}
    }});

    buildTable(
      document.getElementById('tblPrefetch'),
      ['Last run (UTC)', 'Run count', 'Executable', 'PF path'],
      pfEntries.slice(0, 20).map(x => [
        (x.last_run_times_utc && x.last_run_times_utc[0]) ? x.last_run_times_utc[0] : (x.pf_mtime_utc || ''),
        x.run_count ?? '',
        x.executable,
        fmtShort(x.pf_path, 80)
      ])
    );

    // Browser history chart + table
    const bh = payload.browser_history;
    const profiles = bh?.profiles || [];
    const byBrowser = new Map();
    for (const p of profiles) {{
      const b = p.browser || '(unknown)';
      byBrowser.set(b, (byBrowser.get(b) || 0) + (p.item_count || 0));
    }}
    const rows = [...byBrowser.entries()].sort((a,b)=>b[1]-a[1]);
    document.getElementById('historyHint').textContent = (bh?.errors && bh.errors.length) ? ('Uyarı: ' + bh.errors[0]) : '';

    new Chart(document.getElementById('chartHistory'), {{
      type: 'doughnut',
      data: {{
        labels: rows.map(r => r[0]),
        datasets: [{{
          data: rows.map(r => r[1]),
          backgroundColor: [
            'rgba(96,165,250,0.7)',
            'rgba(52,211,153,0.7)',
            'rgba(251,191,36,0.7)',
            'rgba(251,113,133,0.7)',
          ],
        }}]
      }},
      options: {{
        plugins: {{ legend: {{ labels: {{ color: '#cbd5e1' }} }} }}
      }}
    }});

    const histRows = [];
    for (const p of profiles.slice(0, 10)) {{
      const items = (p.items || []).slice(0, 10);
      for (const it of items) {{
        histRows.push([
          it.last_visit_utc || '',
          p.browser || '',
          p.profile || '',
          {{ __html: '<a href=\"' + (it.url || '') + '\" target=\"_blank\" rel=\"noreferrer\">' + fmtShort((it.url || ''), 90) + '</a>' }},
          fmtShort(it.title || '', 50),
          it.visit_count ?? ''
        ]);
      }}
    }}
    buildTable(
      document.getElementById('tblHistory'),
      ['Last visit (UTC)', 'Browser', 'Profile', 'URL', 'Title', 'Visits'],
      histRows
    );

    // EVTX chart + table
    const evtx = payload.event_logs;
    const sysEvents = evtx?.system_critical_errors || [];
    const pc = providerCounts(sysEvents);
    document.getElementById('evtxHint').textContent = (evtx?.errors && evtx.errors.length) ? ('Uyarı: ' + evtx.errors[0]) : '';

    new Chart(document.getElementById('chartEvtxProviders'), {{
      type: 'bar',
      data: {{
        labels: pc.labels.map(x => fmtShort(x, 26)),
        datasets: [{{
          label: 'Count',
          data: pc.data,
          backgroundColor: 'rgba(251,113,133,0.45)',
          borderColor: 'rgba(251,113,133,0.95)',
          borderWidth: 1
        }}]
      }},
      options: {{
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
          x: {{ ticks: {{ color: '#cbd5e1' }} }},
          y: {{ ticks: {{ color: '#cbd5e1' }} }}
        }}
      }}
    }});

    buildTable(
      document.getElementById('tblEvtx'),
      ['Time (UTC)', 'Provider', 'EventID', 'Channel'],
      sysEvents.slice(0, 10).map(e => [e.time_created_utc || '', e.provider || '', e.event_id, e.channel || ''])
    );

    // UserAssist chart + table
    const ua = payload.userassist;
    const uaEntries = ua?.entries || [];
    document.getElementById('uaHint').textContent = (ua?.errors && ua.errors.length) ? ('Uyarı: ' + ua.errors[0]) : '';

    const uaTop = uaEntries.slice(0, 10);
    new Chart(document.getElementById('chartUserAssist'), {{
      type: 'bar',
      data: {{
        labels: uaTop.map(x => fmtShort(x.name || '', 26)),
        datasets: [{{
          label: 'Run count',
          data: uaTop.map(x => (x.run_count == null ? 0 : x.run_count)),
          backgroundColor: 'rgba(167,139,250,0.45)',
          borderColor: 'rgba(167,139,250,0.95)',
          borderWidth: 1
        }}]
      }},
      options: {{
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
          x: {{ ticks: {{ color: '#cbd5e1' }} }},
          y: {{ ticks: {{ color: '#cbd5e1' }} }}
        }}
      }}
    }});

    buildTable(
      document.getElementById('tblUserAssist'),
      ['Last run (UTC)', 'Run count', 'Name', 'GUID'],
      uaEntries.slice(0, 20).map(e => [e.last_run_utc || '', e.run_count ?? '', fmtShort(e.name || '', 120), e.guid || ''])
    );

    // Timeline chart + table
    const tl = payload.timeline;
    const tlEvents = tl?.events || [];
    document.getElementById('tlHint').textContent =
      tl ? ('Toplam event: ' + String(tl.total_events ?? tlEvents.length ?? 0)) : 'Timeline üretilmedi (CLI: --timeline).';

    function bucketDay(iso) {{
      try {{ return (iso || '').slice(0, 10); }} catch {{ return ''; }}
    }}
    const counts = new Map();
    for (const e of tlEvents) {{
      const d = bucketDay(e.timestamp_utc);
      if (!d) continue;
      counts.set(d, (counts.get(d) || 0) + 1);
    }}
    const days = [...counts.entries()].sort((a,b) => a[0].localeCompare(b[0]));
    new Chart(document.getElementById('chartTimeline'), {{
      type: 'line',
      data: {{
        labels: days.map(x => x[0]),
        datasets: [{{
          label: 'Olay sayısı',
          data: days.map(x => x[1]),
          borderColor: 'rgba(96,165,250,0.95)',
          backgroundColor: 'rgba(96,165,250,0.15)',
          fill: true,
          tension: 0.3,
          pointRadius: 4,
          pointHoverRadius: 6
        }}]
      }},
      options: {{
        plugins: {{ legend: {{ labels: {{ color: '#cbd5e1' }} }} }},
        scales: {{
          x: {{ ticks: {{ color: '#cbd5e1' }} }},
          y: {{ ticks: {{ color: '#cbd5e1' }} }}
        }}
      }}
    }});

    buildTable(
      document.getElementById('tblTimeline'),
      ['Time (UTC)', 'Source', 'Type', 'Subject', 'Details'],
      tlEvents.slice(0, 50).map(e => [e.timestamp_utc || '', e.source || '', e.event_type || '', fmtShort(e.subject || '', 90), fmtShort(e.details || '', 110)])
    );

    // Persistence chart + table
    const pers = payload.persistence;
    const persSus = pers?.suspicious || [];
    document.getElementById('persHint').textContent =
      pers ? ('Şüpheli: ' + String(persSus.length || 0) + ' • İmza kontrolü: ' + String(pers.signature_checks_performed ?? 0)) : 'Persistence toplanmadı (CLI: --persistence).';

    const svcItems = (pers && pers.services && pers.services.items) ? pers.services.items : [];
    const counts2 = [
      ['Run keys', (pers?.run_keys || []).length],
      ['Startup', (pers?.startup_folder || []).length],
      ['Services', svcItems.length],
      ['Tasks', (pers?.scheduled_tasks || []).length],
      ['Suspicious', persSus.length],
    ];
    new Chart(document.getElementById('chartPersistence'), {{
      type: 'bar',
      data: {{
        labels: counts2.map(x => x[0]),
        datasets: [{{
          label: 'Count',
          data: counts2.map(x => x[1]),
          backgroundColor: 'rgba(34,197,94,0.25)',
          borderColor: 'rgba(34,197,94,0.9)',
          borderWidth: 1
        }}]
      }},
      options: {{
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
          x: {{ ticks: {{ color: '#cbd5e1' }} }},
          y: {{ ticks: {{ color: '#cbd5e1' }} }}
        }}
      }}
    }});

    buildTable(
      document.getElementById('tblPersistence'),
      ['Kind', 'Name', 'Exec', 'Reasons'],
      persSus.slice(0, 30).map(f => [
        f.kind || '',
        fmtShort(f.name || '', 60),
        fmtShort(f.exec_path || '', 80),
        fmtShort((f.suspicious_reasons || []).join(', '), 120),
      ])
    );

    // VirusTotal chart + table
    const vt = payload.virustotal;
    const vtReports = vt?.reports || [];
    document.getElementById('vtHint').textContent =
      !vt ? 'VirusTotal çalıştırılmadı (CLI: --virustotal).' :
      (vt.enabled === false ? 'Devre dışı: VT_API_KEY tanımlı değil.' : ('Sorgu: ' + String(vt.checked ?? vtReports.length ?? 0)));

    const vtTop = vtReports.slice(0, 10);
    new Chart(document.getElementById('chartVT'), {{
      type: 'bar',
      data: {{
        labels: vtTop.map(r => fmtShort(r.meaningful_name || r.sha256 || '', 22)),
        datasets: [
          {{
            label: 'malicious',
            data: vtTop.map(r => (r.malicious == null ? 0 : r.malicious)),
            backgroundColor: 'rgba(251,113,133,0.55)',
            borderColor: 'rgba(251,113,133,0.95)',
            borderWidth: 1
          }},
          {{
            label: 'suspicious',
            data: vtTop.map(r => (r.suspicious == null ? 0 : r.suspicious)),
            backgroundColor: 'rgba(251,191,36,0.45)',
            borderColor: 'rgba(251,191,36,0.95)',
            borderWidth: 1
          }}
        ]
      }},
      options: {{
        responsive: true,
        plugins: {{
          legend: {{ labels: {{ color: '#cbd5e1' }} }}
        }},
        scales: {{
          x: {{ ticks: {{ color: '#cbd5e1' }} }},
          y: {{ ticks: {{ color: '#cbd5e1' }} }}
        }}
      }}
    }});

    buildTable(
      document.getElementById('tblVT'),
      ['SHA256', 'Name', 'Malicious', 'Suspicious', 'Reputation', 'Link', 'Error'],
      vtReports.slice(0, 50).map(r => [
        fmtShort(r.sha256 || '', 16),
        fmtShort(r.meaningful_name || '', 40),
        r.malicious ?? '',
        r.suspicious ?? '',
        r.reputation ?? '',
        r.permalink ? {{ __html: '<a href=\"' + r.permalink + '\" target=\"_blank\" rel=\"noreferrer\">VT</a>' }} : '',
        fmtShort(r.error || '', 40),
      ])
    );

    // Highlight: malicious>0 => red, suspicious>0 => yellow
    try {{
      const tbl = document.getElementById('tblVT');
      const rows = tbl ? tbl.querySelectorAll('tbody tr') : [];
      rows.forEach((tr) => {{
        const tds = tr.querySelectorAll('td');
        const m = parseInt((tds[2]?.textContent || '0').trim(), 10) || 0;
        const s = parseInt((tds[3]?.textContent || '0').trim(), 10) || 0;
        if (m > 0) tr.classList.add('row-bad');
        else if (s > 0) tr.classList.add('row-warn');
      }});
    }} catch (e) {{}}

    // Search filter across tables (simple substring match)
    const q = document.getElementById('q');
    const tableIds = ['tblBiggest', 'tblHistory', 'tblPrefetch', 'tblEvtx', 'tblUserAssist', 'tblTimeline', 'tblPersistence', 'tblVT'];
    function applyFilter() {{
      const needle = (q.value || '').toLowerCase().trim();
      for (const id of tableIds) {{
        const tbl = document.getElementById(id);
        if (!tbl) continue;
        const rows = tbl.querySelectorAll('tbody tr');
        rows.forEach(r => {{
          const text = r.textContent.toLowerCase();
          r.style.display = (!needle || text.includes(needle)) ? '' : 'none';
        }});
      }}
    }}
    q.addEventListener('input', applyFilter);
  </script>
</body>
</html>
"""

    html_path.write_text(html, encoding="utf-8")
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return html_path, json_path

