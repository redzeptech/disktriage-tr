from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, Iterable, Optional

from .logging_utils import get_logger

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1MB
logger = get_logger("io")


def hash_file(path: Path, *, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Dict[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()

    logger.debug("Hashing file: %s", path)
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)

    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}


def safe_stat(p: Path) -> Optional[os.stat_result]:
    try:
        return p.stat()
    except Exception:
        logger.debug("stat failed: %s", p, exc_info=True)
        return None


def iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return

    try:
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            base = Path(dirpath)
            for name in filenames:
                yield base / name
    except Exception:
        logger.warning("Directory walk failed: %s", root, exc_info=True)

