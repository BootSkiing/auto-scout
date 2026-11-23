#!/usr/bin/env python3
"""Tests for the stage output-cleanup helpers.

Run directly:  python3 tests/test_cleanup.py
Or with pytest: pytest tests/test_cleanup.py
"""
import logging
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.utils import clean_stage_dir, wipe_stage_dir

_LOG = logging.getLogger("test")


def _populate() -> Path:
    d = Path(tempfile.mkdtemp())
    (d / "domains_approved.txt").write_text("keep")   # human-approved -> preserve
    (d / "asns_approved.json").write_text("keep")     # *_approved.* -> preserve
    (d / "progress.json").write_text("{}")            # resume state -> preserve
    (d / "rdns_raw.json").write_text("stale")         # regenerated -> remove
    (d / "nmap_results_1.xml").write_text("stale")    # regenerated -> remove
    sub = d / "bbot_output"
    sub.mkdir()
    (sub / "scan.txt").write_text("stale")            # regenerated dir -> remove
    return d


def test_clean_stage_dir_preserves_approved_and_progress():
    d = _populate()
    removed = clean_stage_dir(d, logger=_LOG)
    remaining = sorted(p.name for p in d.iterdir())
    assert remaining == ["asns_approved.json", "domains_approved.txt", "progress.json"], remaining
    assert removed == 3  # rdns_raw.json, nmap_results_1.xml, bbot_output/


def test_clean_stage_dir_custom_preserve():
    d = _populate()
    clean_stage_dir(d, preserve=("*.json",), logger=_LOG)
    remaining = sorted(p.name for p in d.iterdir())
    # Only .json files survive under this preserve glob.
    assert remaining == ["asns_approved.json", "progress.json", "rdns_raw.json"], remaining


def test_wipe_stage_dir_removes_everything():
    d = _populate()
    wipe_stage_dir(d, logger=_LOG)
    assert list(d.iterdir()) == []


def test_missing_dir_is_noop():
    missing = Path(tempfile.mkdtemp()) / "nope"
    assert clean_stage_dir(missing, logger=_LOG) == 0
    assert wipe_stage_dir(missing, logger=_LOG) == 0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
