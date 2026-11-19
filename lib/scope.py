"""Centralized out-of-scope filtering.

Three kinds of out-of-scope items, loaded once per stage from seed files and
applied uniformly: relevant items are dropped BEFORE a stage does its work (to
save queries/time) and AFTER discovery, before the human review gate (so the
reviewer only sees in-scope candidates).

  - terms:   search INPUT terms. Governs the corporation list in s2 (ASN search)
             and the whois names/orgs/emails in s4. Exact, case-insensitive match
             on the term value.
  - asns:    ASNs discovered in s2. Matched on normalized bare-numeric form
             ("AS1234" / "as1234" / "1234" are equivalent).
  - domains: domains discovered in s3/s4/s6 and merged in s5. Matches the domain
             itself AND any subdomain of it (an entry "example.com" removes
             "example.com" and "a.example.com", but not "notexample.com").
             Case-insensitive, NOT regex. The separate, intentionally-regex
             cleanup.excluded_domain_patterns feature is unrelated and still lives
             in lib.utils.filter_excluded.

Every removal is deleted (not kept-and-deselected), recorded to
<stage_dir>/scope_removed.json, and announced with one standard log line.
"""
import logging
from pathlib import Path

from lib.config import resolve_seed_path
from lib.utils import read_lines, normalize_asn, save_json, load_json


def _normalize_domain(d: str) -> str:
    return d.strip().lower().rstrip(".")


class Scope:
    """Out-of-scope rule set loaded once from the seed files."""

    def __init__(self, config: dict):
        self.terms = {
            t.strip().lower()
            for t in read_lines(resolve_seed_path(config, "out_of_scope_terms"))
        }
        self.asns = {
            normalize_asn(a)
            for a in read_lines(resolve_seed_path(config, "out_of_scope_asns"))
        }
        self.domains = {
            nd
            for d in read_lines(resolve_seed_path(config, "out_of_scope_domains"))
            if (nd := _normalize_domain(d))
        }

    # --- matching -----------------------------------------------------------
    def match_term(self, value: str) -> bool:
        return value.strip().lower() in self.terms

    def match_asn(self, asn: str) -> bool:
        return normalize_asn(asn) in self.asns

    def match_domain(self, domain: str) -> str | None:
        """Return the scope entry that covers this domain, or None.

        A domain is out of scope if it equals an entry or is a subdomain of one.
        """
        d = _normalize_domain(domain)
        if d in self.domains:
            return d
        for entry in self.domains:
            if d.endswith("." + entry):
                return entry
        return None

    # --- filtering (each returns (kept, removed)) ---------------------------
    def filter_terms(self, items: list, key=None) -> tuple[list, list[dict]]:
        """Filter a list of terms. `key` extracts the term from each item
        (e.g. for s4's (search_type, value) tuples); kept items are returned
        unchanged."""
        kept, removed = [], []
        for it in items:
            value = key(it) if key else it
            if self.match_term(value):
                removed.append({"item": value, "matched": value.strip().lower()})
            else:
                kept.append(it)
        return kept, removed

    def filter_asns(self, entries: list[dict]) -> tuple[list[dict], list[dict]]:
        """Filter a list of ASN result rows (each a dict with an 'asn' key)."""
        kept, removed = [], []
        for e in entries:
            if self.match_asn(e["asn"]):
                removed.append({
                    "item": e["asn"],
                    "matched": normalize_asn(e["asn"]),
                    "description": e.get("description", ""),
                })
            else:
                kept.append(e)
        return kept, removed

    def filter_domains(self, domains: list[str]) -> tuple[list[str], list[dict]]:
        kept, removed = [], []
        for d in domains:
            matched = self.match_domain(d)
            if matched is not None:
                removed.append({"item": d, "matched": matched})
            else:
                kept.append(d)
        return kept, removed

    # --- audit --------------------------------------------------------------
    def record(
        self,
        stage_dir: Path,
        item_type: str,
        phase: str,
        removed: list[dict],
        logger: logging.Logger,
    ):
        """Record removed items to <stage_dir>/scope_removed.json and log a line.

        Idempotent per (item_type, phase): re-running a stage replaces that
        section rather than appending duplicates.
        """
        if not removed:
            return

        path = Path(stage_dir) / "scope_removed.json"
        data = {"terms": [], "asns": [], "domains": []}
        if path.exists():
            try:
                existing = load_json(path)
                if isinstance(existing, dict):
                    data.update(existing)
            except Exception:
                pass

        data[item_type] = [
            e for e in data.get(item_type, []) if e.get("phase") != phase
        ]
        data[item_type].extend({**r, "phase": phase} for r in removed)

        save_json(path, data)
        logger.info(
            f"Removed {len(removed)} out-of-scope {item_type} ({phase}); see {path}"
        )
