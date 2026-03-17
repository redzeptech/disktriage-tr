"""Modül birim testleri."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from disktriage.modules import anonymizer, io, utils


def test_hash_file() -> None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(b"test")
        path = Path(f.name)
    try:
        h = io.hash_file(path)
        assert "sha256" in h
        assert "md5" in h
        assert len(h["sha256"]) == 64
    finally:
        path.unlink()


def test_anonymize_payload() -> None:
    payload = {
        "target": {"path": "C:\\Users\\TestUser\\Documents"},
        "errors": [],
    }
    out = anonymizer.anonymize_payload(payload)
    assert "[HIDDEN]" in out["target"]["path"] or "TestUser" not in out["target"]["path"]


def test_now_utc_iso() -> None:
    s = utils.now_utc_iso()
    assert "T" in s
    assert s.endswith("Z") or "+" in s
