from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

from .anonymizer import anonymize_string

def print_run_summary(*, payload: Dict[str, Any], txt_path: Path, json_path: Path, out_dir: Path) -> None:
    """
    Konsol çıktısını zenginleştirir.

    - Rich yüklüyse tablo şeklinde basar.
    - Değilse düz `print()` ile fallback yapar.
    """
    username = os.environ.get("USERNAME", "")
    computername = os.environ.get("COMPUTERNAME", "")
    try:
        home = str(Path.home())
    except Exception:
        home = ""

    def m(s: str) -> str:
        return anonymize_string(s, username=username, computername=computername, home=home)

    try:
        from rich.console import Console  # type: ignore
        from rich.table import Table  # type: ignore
        from rich.text import Text  # type: ignore

        c = Console(markup=False)

        t = Table(title="DiskTriage TR — Çalıştırma Özeti", show_lines=False)
        t.add_column("Alan", style="bold cyan", no_wrap=True)
        t.add_column("Değer", style="white")

        target = payload.get("target", {}) or {}
        summary = payload.get("summary", {}) or {}

        t.add_row("Target", m(str(target.get("path", ""))))
        t.add_row("Type", str(target.get("type", "")))
        t.add_row("Created (UTC)", m(str(payload.get("created_utc", ""))))
        t.add_row("Inventory count", str(payload.get("inventory_count", "")))
        t.add_row("Total files", str(summary.get("total_files", "")))
        t.add_row("Total size (bytes)", str(summary.get("total_size_bytes", "")))
        t.add_row("TXT report", m(str(txt_path)))
        t.add_row("JSON report", m(str(json_path)))
        t.add_row("HTML report", m(str(out_dir / "reports" / "report.html")))
        t.add_row("Log", m(str(out_dir / "reports" / "disktriage.log")))
        if payload.get("timeline"):
            t.add_row("Timeline CSV", m(str(out_dir / "reports" / "timeline.csv")))

        if payload.get("errors"):
            err = Text(", ".join(payload["errors"]), style="bold yellow")
            t.add_row("Warnings", err)

        c.print(t)
        return
    except Exception:
        # Fallback (Rich yok / import hatası / TTY yok)
        pass

    print(f"Rapor üretildi: {m(str(txt_path))}")
    print(f"JSON çıktı:    {m(str(json_path))}")
    print(f"HTML rapor:    {m(str(out_dir / 'reports' / 'report.html'))}")
    print(f"Log:          {m(str(out_dir / 'reports' / 'disktriage.log'))}")

