from __future__ import annotations

import logging
import queue
from pathlib import Path
from typing import Optional


def configure_logging(
    *,
    out_dir: Path,
    level: str = "INFO",
    log_queue: Optional[queue.Queue] = None,
) -> Path:
    """
    Configures a single application logger that logs to:
      - stderr (INFO+)
      - out_dir/reports/disktriage.log (DEBUG+)
    Returns the log file path.
    """
    reports_dir = out_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    log_path = reports_dir / "disktriage.log"

    logger = logging.getLogger("disktriage")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Dashboard mode: log_queue ile her seferinde yeni handler eklenebilsin.
    if log_queue is not None:
        logger.handlers.clear()
        logger._configured = False  # type: ignore[attr-defined]

    # Avoid duplicate handlers on repeated runs (e.g., tests).
    if getattr(logger, "_configured", False):
        return log_path

    fmt = logging.Formatter(
        fmt="%(asctime)sZ [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    # File handler (UTF-8)
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    # Console handler
    sh = logging.StreamHandler()
    sh.setLevel(getattr(logging, level.upper(), logging.INFO))
    sh.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(sh)

    if log_queue is not None:
        # QueueHandler puts LogRecord; we need formatted strings for streaming.
        class _QueueStringHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                try:
                    log_queue.put_nowait(self.format(record))
                except Exception:
                    self.handleError(record)

        qsh = _QueueStringHandler()
        qsh.setLevel(logging.DEBUG)
        qsh.setFormatter(fmt)
        logger.addHandler(qsh)

    logger._configured = True  # type: ignore[attr-defined]
    logger.debug("Logging configured. level=%s log_path=%s", level, log_path)
    return log_path


def get_logger(name: str) -> logging.Logger:
    # Child of "disktriage" for consistent routing.
    return logging.getLogger(f"disktriage.{name}")

