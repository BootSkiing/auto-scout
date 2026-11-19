#!/usr/bin/env python3
"""Tests for lib.scope out-of-scope matching.

Run directly:  python3 tests/test_scope.py
Or with pytest: pytest tests/test_scope.py
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.scope import Scope


def _make_scope(domains=(), terms=(), asns=()) -> Scope:
    tmp = Path(tempfile.mkdtemp())
    (tmp / "d.txt").write_text("\n".join(domains) + "\n")
    (tmp / "t.txt").write_text("\n".join(terms) + "\n")
    (tmp / "a.txt").write_text("\n".join(asns) + "\n")
    cfg = {"seeds": {
        "out_of_scope_domains": str(tmp / "d.txt"),
        "out_of_scope_terms": str(tmp / "t.txt"),
        "out_of_scope_asns": str(tmp / "a.txt"),
    }}
    return Scope(cfg)


def test_domain_exact_and_subdomain_match():
    s = _make_scope(domains=["example.com"])
    kept, removed = s.filter_domains([
        "example.com",            # exact -> removed
        "a.example.com",          # subdomain -> removed
        "deep.sub.example.com",   # nested subdomain -> removed
        "notexample.com",         # NOT a subdomain -> kept
        "example.com.evil.net",   # suffix trick -> kept
        "other.org",              # unrelated -> kept
    ])
    assert kept == ["notexample.com", "example.com.evil.net", "other.org"]
    assert {r["item"] for r in removed} == {
        "example.com", "a.example.com", "deep.sub.example.com"
    }
    assert all(r["matched"] == "example.com" for r in removed)


def test_domain_match_is_case_insensitive():
    s = _make_scope(domains=["Example.COM"])
    kept, removed = s.filter_domains(["EXAMPLE.com", "A.Example.Com"])
    assert kept == []
    assert len(removed) == 2


def test_domain_trailing_dot_normalized():
    s = _make_scope(domains=["example.com."])
    assert s.match_domain("a.example.com.") == "example.com"


def test_term_exact_match_only():
    s = _make_scope(terms=["staging", "internal-test"])
    kept, removed = s.filter_terms(["Acme", "STAGING", "staging-ish", "internal-test"])
    assert kept == ["Acme", "staging-ish"]  # substring is NOT a match
    assert {r["item"] for r in removed} == {"STAGING", "internal-test"}


def test_term_filter_with_key():
    s = _make_scope(terms=["staging"])
    jobs = [("company", "Acme"), ("email", "staging"), ("name", "staging")]
    kept, removed = s.filter_terms(jobs, key=lambda j: j[1])
    assert kept == [("company", "Acme")]
    assert len(removed) == 2


def test_asn_normalized_match():
    s = _make_scope(asns=["AS100", "200"])
    entries = [
        {"asn": "100", "description": "x"},     # bare form matches AS100
        {"asn": "AS200", "description": "y"},    # prefixed form matches 200
        {"asn": "300", "description": "z"},      # no match
    ]
    kept, removed = s.filter_asns(entries)
    assert [e["asn"] for e in kept] == ["300"]
    assert {r["item"] for r in removed} == {"100", "AS200"}


def test_record_is_idempotent_per_type_and_phase():
    s = _make_scope(domains=["example.com"])
    stage_dir = Path(tempfile.mkdtemp())

    import logging
    log = logging.getLogger("test")

    removed = [{"item": "a.example.com", "matched": "example.com"}]
    s.record(stage_dir, "domains", "post", removed, log)
    s.record(stage_dir, "domains", "post", removed, log)  # re-run: replace, not append

    data = json.loads((stage_dir / "scope_removed.json").read_text())
    assert len(data["domains"]) == 1
    assert data["domains"][0]["phase"] == "post"
    assert data["terms"] == [] and data["asns"] == []


def test_record_noop_on_empty():
    s = _make_scope()
    stage_dir = Path(tempfile.mkdtemp())
    import logging
    s.record(stage_dir, "domains", "post", [], logging.getLogger("test"))
    assert not (stage_dir / "scope_removed.json").exists()


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
