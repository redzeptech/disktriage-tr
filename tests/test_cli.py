"""CLI ve temel akış testleri."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from disktriage.cli import build_arg_parser, build_payload, run


def test_build_arg_parser() -> None:
    ap = build_arg_parser()
    args = ap.parse_args(["."])
    assert args.target == "."
    assert args.workers == 8


def test_build_payload_directory() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp)
        payload = build_payload(target=target, no_hash=True)
        assert payload["target"]["type"] == "directory"
        assert payload["inventory_count"] == 0
        assert "errors" in payload


def test_run_minimal() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp)
        out_dir = Path(tmp) / "out"
        txt_path, json_path, payload = run(
            target=target,
            out_dir=out_dir,
            max_files=100,
            workers=0,
            no_hash=True,
            include_prefetch=False,
            prefetch_dir=None,
            prefetch_max=200,
            include_browser_history=False,
            history_max=50,
            include_evtx=False,
            evtx_days=7,
            evtx_max=50,
            evtx_path=None,
            include_userassist=False,
            userassist_max=200,
            anonymize=True,
            include_timeline=False,
            timeline_embed_max=1000,
            timeline_csv_max=20000,
            include_persistence=False,
            persistence_new_service_days=7,
            sig_check_max=50,
            include_virustotal=False,
            vt_max=25,
        )
        assert txt_path.exists()
        assert json_path.exists()
        assert payload["inventory_count"] >= 0
