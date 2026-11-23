#!/usr/bin/env python3
"""Tests for stage 7 masscan parsing, port-arg selection, and port-set grouping.

Run directly:  python3 tests/test_port_scan.py
Or with pytest: pytest tests/test_port_scan.py

No network or external binaries are used.
"""
import logging
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import stages.s7_port_scan as s7

_LOG = logging.getLogger("test")


def _write(name: str, text: str) -> str:
    p = Path(tempfile.mkdtemp()) / name
    p.write_text(text)
    return str(p)


def test_parse_masscan_groups_ports_and_filters_proto():
    f = _write("m.json", (
        '[\n'
        '{ "ip": "1.1.1.1", "ports": [ {"port": 443, "proto": "tcp", "status": "open"} ] }\n,\n'
        '{ "ip": "1.1.1.1", "ports": [ {"port": 80, "proto": "tcp", "status": "open"} ] }\n,\n'
        '{ "ip": "2.2.2.2", "ports": [ {"port": 48291, "proto": "tcp", "status": "open"} ] }\n,\n'
        '{ "ip": "3.3.3.3", "ports": [ {"port": 53, "proto": "udp", "status": "open"} ] }\n'
        ']'
    ))
    got = s7._parse_masscan(f, _LOG)
    # ports grouped+sorted per IP; the high port is kept; the udp record dropped.
    assert got == {"1.1.1.1": [80, 443], "2.2.2.2": [48291]}, got


def test_parse_masscan_salvages_interrupted_output():
    # No closing bracket, trailing comma -- what a killed multi-day scan leaves.
    f = _write("partial.json", (
        '[\n'
        '{ "ip": "1.1.1.1", "ports": [ {"port": 443, "proto": "tcp", "status": "open"} ] }\n,\n'
        '{ "ip": "2.2.2.2", "ports": [ {"port": 22, "proto": "tcp", "status": "open"} ] }\n,'
    ))
    assert s7._parse_masscan(f, _LOG) == {"1.1.1.1": [443], "2.2.2.2": [22]}


def test_parse_masscan_empty_and_missing():
    assert s7._parse_masscan(_write("empty.json", ""), _LOG) == {}
    assert s7._parse_masscan(str(Path(tempfile.mkdtemp()) / "nope.json"), _LOG) == {}


def test_masscan_port_args_by_mode():
    full, label = s7._masscan_port_args({"port_scan": {"scan_mode": "full"}})
    assert full == ["-p", "1-65535"] and label == "all-65535"
    top, label = s7._masscan_port_args(
        {"port_scan": {"scan_mode": "top-ports", "masscan_top_ports": 1000}})
    assert top == ["--top-ports=1000"] and label == "top-1000"


def test_port_set_grouping():
    # Mirrors the grouping in run(): hosts with the same open-port set share one
    # nmap job; each host scanned by its representative hostname (or IP).
    scannable = {"1.1.1.1": [80, 443], "10.0.0.9": [80, 443], "2.2.2.2": [48291]}
    ip2h = {"1.1.1.1": ["a.example.com"], "10.0.0.9": ["b.example.com"]}
    groups: dict[tuple, list[str]] = {}
    for ip, ports in scannable.items():
        names = sorted(ip2h.get(ip, []))
        groups.setdefault(tuple(ports), []).append(names[0] if names else ip)
    assert groups[(80, 443)] == ["a.example.com", "b.example.com"]
    assert groups[(48291,)] == ["2.2.2.2"]  # unnamed -> scanned by IP


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
