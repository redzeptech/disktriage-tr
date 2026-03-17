from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    """
    PyInstaller ile tek dosya (portable) .exe üretir.

    Gereksinim:
      pip install pyinstaller

    Çalıştırma:
      python build.py
    """
    root = Path(__file__).resolve().parent
    entry = root / "main.py"
    dist = root / "dist"
    build_dir = root / "build"

    if not entry.exists():
        print("Giriş dosyası bulunamadı: main.py", file=sys.stderr)
        return 2

    pyinstaller = shutil.which("pyinstaller")
    if not pyinstaller:
        print("PyInstaller bulunamadı. Kurulum:", file=sys.stderr)
        print("  pip install pyinstaller", file=sys.stderr)
        return 2

    cmd = [
        pyinstaller,
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        "disktriage-tr",
        str(entry),
    ]

    print("Komut:", " ".join(cmd))
    p = subprocess.run(cmd, cwd=str(root))
    if p.returncode != 0:
        return int(p.returncode)

    exe = dist / "disktriage-tr.exe"
    if exe.exists():
        print("Build OK:", exe)
        return 0

    print("Build tamamlandı ama exe bulunamadı. dist/ klasörünü kontrol edin.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

