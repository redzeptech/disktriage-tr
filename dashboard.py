"""
DiskTriage TR - Streamlit Dashboard.

Tarama başlatma, ilerleme çubuğu ve anlık log akışı sağlar.
"""

from __future__ import annotations

import queue
import threading
from pathlib import Path

import streamlit as st

from disktriage.cli import run
from disktriage.modules.logging_utils import configure_logging

st.set_page_config(
    page_title="DiskTriage TR",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 DiskTriage TR - Adli Bilişim Ön İnceleme")
st.caption("Tarama başlatın, ilerlemeyi ve logları anlık takip edin.")

# Sidebar: Tarama ayarları
with st.sidebar:
    st.header("Tarama Ayarları")

    target_path = st.text_input(
        "Hedef (klasör veya dosya)",
        value=".",
        help="İncelenecek klasör veya dosya yolu",
    )
    out_path = st.text_input(
        "Çıktı klasörü",
        value="./disktriage_out",
        help="Raporların kaydedileceği klasör",
    )
    max_files = st.number_input("Maks. dosya sayısı", min_value=1000, value=200_000, step=10_000)
    workers = st.number_input("Worker sayısı", min_value=0, value=8, step=1)
    anonymize = st.checkbox("Kişisel verileri maskele", value=True)

    st.divider()
    st.subheader("Opsiyonel Modüller")
    include_prefetch = st.checkbox("Prefetch", value=False)
    include_browser = st.checkbox("Tarayıcı geçmişi", value=False)
    include_evtx = st.checkbox("Event Log (EVTX)", value=False)
    include_userassist = st.checkbox("UserAssist", value=False)
    include_persistence = st.checkbox("Persistence (Startup/Services)", value=False)
    include_virustotal = st.checkbox("VirusTotal (VT_API_KEY gerekir)", value=False)
    include_timeline = st.checkbox("Zaman tüneli (Timeline)", value=False)


def _run_scan(
    target: Path,
    out_dir: Path,
    log_queue: queue.Queue,
    done: threading.Event,
    result: list,
) -> None:
    """Tarama işlemini thread içinde çalıştırır. Sonuç result listesine yazılır."""
    try:
        configure_logging(out_dir=out_dir, level="INFO", log_queue=log_queue)
        run(
            target=target,
            out_dir=out_dir,
            max_files=max_files,
            workers=workers,
            no_hash=False,
            include_prefetch=include_prefetch,
            prefetch_dir=None,
            prefetch_max=200,
            include_browser_history=include_browser,
            history_max=50,
            include_evtx=include_evtx,
            evtx_days=7,
            evtx_max=50,
            evtx_path=None,
            include_userassist=include_userassist,
            userassist_max=200,
            anonymize=anonymize,
            include_timeline=include_timeline,
            timeline_embed_max=1000,
            timeline_csv_max=20000,
            include_persistence=include_persistence,
            persistence_new_service_days=7,
            sig_check_max=50,
            include_virustotal=include_virustotal,
            vt_max=25,
        )
        result.append(("ok", None))
    except FileNotFoundError as e:
        result.append(("error", str(e)))
    except Exception as e:
        result.append(("error", f"{type(e).__name__}: {e}"))
    finally:
        done.set()


# Ana içerik
if "scan_done" not in st.session_state:
    st.session_state.scan_done = None
if "scan_error" not in st.session_state:
    st.session_state.scan_error = None

col1, col2, _ = st.columns([1, 1, 3])
with col1:
    start_btn = st.button("▶️ Tarama Başlat", type="primary", use_container_width=True)

if start_btn:
    target = Path(target_path).expanduser().resolve()
    out_dir = Path(out_path).expanduser().resolve()

    if not target.exists():
        st.error(f"Hedef bulunamadı: {target}")
    else:
        log_queue: queue.Queue = queue.Queue()
        done = threading.Event()
        result: list = []

        with st.status("Tarama devam ediyor...", state="running", expanded=True) as status:
            progress_bar = st.progress(0, text="Başlatılıyor...")
            log_container = st.container()

            thread = threading.Thread(
                target=_run_scan,
                args=(target, out_dir, log_queue, done, result),
            )
            thread.start()

            # Log akışı ve ilerleme
            log_text = ""
            step = 0
            steps = [
                "Hash / Payload",
                "Envanter taraması",
                "Prefetch",
                "Tarayıcı geçmişi",
                "Event Log",
                "UserAssist",
                "Persistence",
                "VirusTotal",
                "Timeline",
                "Rapor yazılıyor",
            ]
            max_progress = len(steps)

            with log_container:
                log_placeholder = st.empty()
                while thread.is_alive():
                    try:
                        line = log_queue.get(timeout=0.2)
                        log_text += line + "\n"
                        log_placeholder.code(log_text[-8000:], language="log")
                        # Log mesajlarından aşama çıkar
                        if "Inventory progress" in line or "Building inventory" in line:
                            step = max(step, 1)
                        elif "prefetch" in line.lower():
                            step = max(step, 2)
                        elif "browser" in line.lower():
                            step = max(step, 3)
                        elif "evtx" in line.lower() or "event" in line.lower():
                            step = max(step, 4)
                        elif "userassist" in line.lower():
                            step = max(step, 5)
                        elif "persistence" in line.lower():
                            step = max(step, 6)
                        elif "virustotal" in line.lower():
                            step = max(step, 7)
                        elif "timeline" in line.lower():
                            step = max(step, 8)
                        elif "report" in line.lower() or "Run finished" in line:
                            step = max(step, 9)
                        progress = min(step + 1, max_progress) / max_progress
                        progress_bar.progress(progress, text=steps[min(step, max_progress - 1)])
                    except queue.Empty:
                        pass

            thread.join()
            # Kalan logları oku
            while not log_queue.empty():
                try:
                    line = log_queue.get_nowait()
                    log_text += line + "\n"
                except queue.Empty:
                    break
            log_placeholder.code(log_text[-8000:], language="log")
            progress_bar.progress(1.0, text="Tamamlandı")

        status.update(label="Tarama tamamlandı", state="complete")
        if result and result[0][0] == "ok":
            st.session_state.scan_done = True
            st.session_state.scan_error = None
            st.success(f"Raporlar kaydedildi: {out_dir}")
            st.info(f"HTML rapor: {out_dir / 'reports' / 'report.html'}")
        else:
            err_msg = result[0][1] if result else "Bilinmeyen hata"
            st.error(f"Tarama hatası: {err_msg}")
            st.session_state.scan_done = False
            st.session_state.scan_error = err_msg

if st.session_state.scan_done:
    st.balloons()
