#!/usr/bin/env python3
"""Tests for the stage 7 resolution gate and its underscore-label filter.

Run directly:  python3 tests/test_resolution_gate.py
Or with pytest: pytest tests/test_resolution_gate.py

DNS resolution is monkeypatched so these tests do no network I/O.
"""
import logging
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.utils import has_underscore_label, load_json
import stages.s7_port_scan as s7

_LOG = logging.getLogger("test")


def test_underscore_label_detects_service_and_wildcard_names():
    # Not hosts -> True (filtered)
    assert has_underscore_label("_dmarc.example.com")
    assert has_underscore_label("_acme-challenge.example.com")
    assert has_underscore_label("_sip._tcp.example.com")          # label mid-name
    assert has_underscore_label("_wildcard.api.example.com")      # CT-log artifact
    assert has_underscore_label("_wildcard.example.com")
    # Real hosts -> False (kept)
    assert not has_underscore_label("api.example.com")
    assert not has_underscore_label("www.example.com")
    assert not has_underscore_label("example.com")
    # An underscore inside a label (not a prefix) is not a service label
    assert not has_underscore_label("foo_bar.example.com")


def test_gate_filters_labels_resolves_rest_and_audits(monkeypatch):
    # Fake DNS: api/www resolve, dead does not; _wildcard never reaches resolve.
    resolved = {
        "api.example.com": ["203.0.113.10"],
        "www.example.com": ["203.0.113.10"],   # same IP as api -> grouped
        "mail.example.com": ["203.0.113.20"],
    }

    def fake_resolve(hostnames, logger):
        ip_map: dict[str, list[str]] = {}
        unresolved: list[str] = []
        for h in hostnames:
            ips = resolved.get(h)
            if ips:
                for ip in ips:
                    ip_map.setdefault(ip, [])
                    if h not in ip_map[ip]:
                        ip_map[ip].append(h)
            else:
                unresolved.append(h)
        return ip_map, unresolved

    monkeypatch.setattr(s7, "_resolve_to_ips", fake_resolve)

    stage_dir = Path(tempfile.mkdtemp())
    hostnames = [
        "api.example.com",
        "www.example.com",
        "mail.example.com",
        "dead.example.com",          # resolves to nothing
        "_dmarc.example.com",        # filtered pre-resolution
        "_wildcard.api.example.com", # filtered pre-resolution
    ]

    ip_map = s7._resolution_gate(hostnames, stage_dir, _LOG)

    # Two unique IPs; api+www grouped under one of them.
    assert set(ip_map.keys()) == {"203.0.113.10", "203.0.113.20"}
    assert sorted(ip_map["203.0.113.10"]) == ["api.example.com", "www.example.com"]
    assert ip_map["203.0.113.20"] == ["mail.example.com"]

    # Underscore labels never hit the resolver.
    assert "_dmarc.example.com" not in str(ip_map)
    assert "_wildcard.api.example.com" not in str(ip_map)

    # Audit records both the filtered labels and the dead name.
    audit = load_json(stage_dir / "resolution_gate.json")
    assert audit["input_hostnames"] == 6
    assert audit["filtered_service_labels"] == [
        "_dmarc.example.com",
        "_wildcard.api.example.com",
    ]
    assert audit["unresolved_hostnames"] == ["dead.example.com"]
    assert audit["resolved_ip_count"] == 2


def _run_if_main():
    # Minimal monkeypatch shim so the file runs without pytest installed.
    class _MP:
        def __init__(self):
            self._undo = []

        def setattr(self, obj, name, value):
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

        def undo(self):
            for obj, name, old in reversed(self._undo):
                setattr(obj, name, old)

    import inspect

    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        mp = _MP()
        try:
            if "monkeypatch" in inspect.signature(fn).parameters:
                fn(mp)
            else:
                fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
        finally:
            mp.undo()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    _run_if_main()
