#!/usr/bin/env python3
"""
Stage 3 (bulk variant): Reverse DNS from THC's monthly bulk snapshot.

This is a drop-in alternative to stages/s3_reverse_dns.py that avoids the
per-IP THC API (and its 0.5 req/s rate limit, ~23h for a full scan) by querying
THC's published monthly bulk dataset locally with DuckDB. It produces the exact
same outputs in the s3_rdns stage dir (domains_review.txt, rdns_raw.json, then
domains_approved.txt via the review gate), so downstream stages are unchanged.

Coverage is identical to the API scan: it expands the s2 CIDR ranges to the same
target IP set (normalize_to_24 -> expand, which skips each /24's network and
broadcast, exactly as s3 does) and hash-joins that set against the snapshot.
The only trade-off vs the live API is freshness: the bulk file is a monthly
snapshot, not continuously updated.

Prerequisites (one-time):
  1. Obtain the decompressed parquet. THC publishes it gzipped on Hugging Face
     (rdns-<month>.parquet.gz, ~51GB compressed / ~79GB uncompressed). Note that
     Hugging Face is blocked by this network's Zscaler policy, so the file must
     be fetched off-network and copied onto this host. DuckDB cannot read a
     gzipped parquet directly, so decompress it first:
         gunzip rdns-oct.parquet.gz          # -> rdns-oct.parquet (~79GB)
     Ensure ~130GB free during decompression.
  2. Install the DuckDB CLI (not blocked by the proxy, unlike PyPI):
         curl https://install.duckdb.org | sh
  3. Point config at the file:
         reverse_dns.bulk.parquet_path: /path/to/rdns-oct.parquet
     (or pass --parquet on the command line).

Run:
    python stages/s3_rdns_bulk.py --parquet /path/to/rdns-oct.parquet
Stop any running API-based s3 scan first; both write into the same stage dir.
"""
import argparse
import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.config import load_config, get_run_dir, get_stage_dir
from lib.logging_setup import setup_logging
from lib.review_gate import review_gate
from lib.utils import (
    read_lines, normalize_to_24, expand_cidr_to_ips,
    deduplicate_domains, filter_excluded, save_json,
)

IP_COLUMN_CANDIDATES = ["ip_address", "ip", "ipaddr", "ip_addr", "addr"]
DOMAIN_COLUMN_CANDIDATES = ["domain", "rdns", "ptr", "name", "hostname", "host", "value"]


def _sql_str(value: str) -> str:
    """Quote a string literal for SQL (single quotes doubled)."""
    return "'" + str(value).replace("'", "''") + "'"


def _sql_ident(value: str) -> str:
    """Quote an identifier for SQL (double quotes doubled)."""
    return '"' + str(value).replace('"', '""') + '"'


def _run_duckdb(duckdb_bin: str, sql: str, logger, timeout: int, json_out: bool = False):
    cmd = [duckdb_bin, "-batch"]
    if json_out:
        cmd.append("-json")
    cmd += ["-c", sql]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        logger.error(
            f"DuckDB binary not found: {duckdb_bin!r}. Install it with "
            f"'curl https://install.duckdb.org | sh' or set reverse_dns.bulk.duckdb_bin."
        )
        return None
    except subprocess.TimeoutExpired:
        logger.error(f"DuckDB query timed out after {timeout}s.")
        return None
    if proc.returncode != 0:
        logger.error(f"DuckDB failed (exit {proc.returncode}): {proc.stderr.strip()[:1000]}")
        return None
    return proc.stdout


def _detect_columns(duckdb_bin: str, parquet: str, bulk_cfg: dict, logger, timeout: int):
    """Return (ip_column, domain_column) or (None, None) on failure."""
    sql = f"DESCRIBE SELECT * FROM read_parquet({_sql_str(parquet)}) LIMIT 0;"
    out = _run_duckdb(duckdb_bin, sql, logger, timeout=min(timeout, 120), json_out=True)
    if out is None:
        return None, None
    try:
        rows = json.loads(out or "[]")
    except json.JSONDecodeError:
        logger.error("Could not parse DuckDB schema output.")
        return None, None

    columns = [r.get("column_name", "") for r in rows]
    lower_map = {c.lower(): c for c in columns}
    types = {r.get("column_name", ""): r.get("column_type", "?") for r in rows}
    logger.info(f"Parquet schema: {types}")

    def pick(configured, candidates, kind):
        if configured:
            if configured in columns:
                return configured
            logger.error(f"Configured {kind} column {configured!r} not in parquet; "
                         f"available: {columns}")
            return None
        for cand in candidates:
            if cand in lower_map:
                return lower_map[cand]
        logger.error(
            f"Could not auto-detect the {kind} column from {columns}. "
            f"Set reverse_dns.bulk.{kind}_column in config."
        )
        return None

    ip_col = pick(bulk_cfg.get("ip_column", ""), IP_COLUMN_CANDIDATES, "ip")
    dom_col = pick(bulk_cfg.get("domain_column", ""), DOMAIN_COLUMN_CANDIDATES, "domain")
    return ip_col, dom_col


def _expand_targets(cidrs: list[str], logger) -> list[str]:
    """Expand CIDRs to the exact IP set s3 queries (per-/24, skipping net/bcast)."""
    ips = set()
    for cidr in cidrs:
        try:
            for subnet in normalize_to_24(cidr):
                ips.update(expand_cidr_to_ips(subnet))
        except ValueError as e:
            logger.warning(f"Skipping invalid CIDR {cidr!r}: {e}")
    return sorted(ips)


def run(run_dir: Path, config: dict, parquet_override: str | None = None) -> bool:
    logger = setup_logging(run_dir, "s3_rdns_bulk")
    stage_dir = get_stage_dir(run_dir, "s3_rdns")
    stage_dir.mkdir(parents=True, exist_ok=True)

    rd = config.get("reverse_dns", {})
    bulk_cfg = rd.get("bulk", {})
    duckdb_bin = bulk_cfg.get("duckdb_bin", "duckdb")
    timeout = int(bulk_cfg.get("query_timeout_seconds", 7200))
    max_expanded = int(bulk_cfg.get("max_expanded_ips", 20_000_000))

    approved_file = stage_dir / "domains_approved.txt"
    if approved_file.exists():
        logger.info("Reverse DNS already completed (approved file exists)")
        return True

    parquet = parquet_override or bulk_cfg.get("parquet_path", "")
    if not parquet:
        logger.error("No parquet file configured. Set reverse_dns.bulk.parquet_path "
                     "or pass --parquet.")
        return False
    if not Path(parquet).exists():
        logger.error(f"Parquet file not found: {parquet}")
        return False
    if parquet.endswith(".gz"):
        logger.error(f"{parquet} is gzipped; DuckDB cannot read it directly. "
                     f"Decompress first: gunzip {parquet}")
        return False

    # Input ranges from stage 2
    ip_ranges_file = run_dir / "s2_asn" / "ip_ranges.txt"
    if not ip_ranges_file.exists():
        logger.error(f"Missing input: {ip_ranges_file}. Run stage 2 first.")
        return False
    cidrs = read_lines(ip_ranges_file)
    if not cidrs:
        logger.warning("No IP ranges to process")
        _write_review(stage_dir, [], config, logger, parquet)
        return review_gate("s3_rdns", stage_dir / "domains_review.txt",
                           approved_file, run_dir, config, logger)

    # Detect schema
    ip_col, dom_col = _detect_columns(duckdb_bin, parquet, bulk_cfg, logger, timeout)
    if not ip_col or not dom_col:
        return False
    logger.info(f"Using ip column {ip_col!r}, domain column {dom_col!r}")

    # Expand to the exact target IP set (parity with the API scan)
    target_ips = _expand_targets(cidrs, logger)
    logger.info(f"Target IPs: {len(target_ips)} (from {len(cidrs)} CIDR ranges)")
    if not target_ips:
        logger.warning("No target IPs after expansion")
        _write_review(stage_dir, [], config, logger, parquet)
        return review_gate("s3_rdns", stage_dir / "domains_review.txt",
                           approved_file, run_dir, config, logger)
    if len(target_ips) > max_expanded:
        logger.error(f"Target IP set ({len(target_ips)}) exceeds max_expanded_ips "
                     f"({max_expanded}). Raise reverse_dns.bulk.max_expanded_ips if "
                     f"this is expected.")
        return False

    with tempfile.TemporaryDirectory(prefix="rdns_bulk_") as tmp:
        targets_path = Path(tmp) / "targets.txt"
        out_path = Path(tmp) / "matches.csv"
        targets_path.write_text("\n".join(target_ips) + "\n")

        sql = (
            f"COPY ("
            f"  SELECT DISTINCT t.ip AS ip, "
            f"         lower(rtrim(trim(p.{_sql_ident(dom_col)}), '.')) AS domain "
            f"  FROM read_csv({_sql_str(str(targets_path))}, header=false, "
            f"               columns={{'ip': 'VARCHAR'}}) t "
            f"  JOIN read_parquet({_sql_str(parquet)}) p "
            f"    ON CAST(p.{_sql_ident(ip_col)} AS VARCHAR) = t.ip "
            f"  WHERE p.{_sql_ident(dom_col)} IS NOT NULL "
            f"    AND length(trim(CAST(p.{_sql_ident(dom_col)} AS VARCHAR))) > 0"
            f") TO {_sql_str(str(out_path))} (FORMAT csv, HEADER false);"
        )
        logger.info(f"Scanning parquet with DuckDB (timeout {timeout}s)...")
        if _run_duckdb(duckdb_bin, sql, logger, timeout=timeout) is None:
            return False

        # Parse (ip, domain) matches
        domains_by_ip: dict[str, list[str]] = {}
        if out_path.exists():
            with open(out_path, newline="") as f:
                for row in csv.reader(f):
                    if len(row) >= 2 and row[1]:
                        domains_by_ip.setdefault(row[0], []).append(row[1])

    for ip in list(domains_by_ip):
        domains_by_ip[ip] = sorted(set(domains_by_ip[ip]))
    total_pairs = sum(len(v) for v in domains_by_ip.values())
    logger.info(f"Matched {len(domains_by_ip)} IPs with {total_pairs} (ip, domain) pairs")

    save_json(stage_dir / "rdns_raw.json", domains_by_ip)

    all_domains = []
    for doms in domains_by_ip.values():
        all_domains.extend(doms)
    all_domains = deduplicate_domains(all_domains)
    logger.info(f"Total unique domains found: {len(all_domains)}")

    _write_review(stage_dir, all_domains, config, logger, parquet)

    return review_gate("s3_rdns", stage_dir / "domains_review.txt",
                       approved_file, run_dir, config, logger)


def _write_review(stage_dir: Path, all_domains: list[str], config: dict, logger, parquet: str):
    """Write domains_review.txt in the same format as the API-based stage."""
    exclusion_patterns = config.get("cleanup", {}).get("excluded_domain_patterns", [])
    if exclusion_patterns and all_domains:
        all_domains, removed = filter_excluded(all_domains, exclusion_patterns)
        if removed:
            logger.info(f"Pre-filtered {len(removed)} domains matching exclusion patterns")

    review_file = stage_dir / "domains_review.txt"
    header = [
        "# REVIEW FILE - Stage 3: Reverse DNS domains",
        f"# Total domains: {len(all_domains)}",
        f"# Source: THC bulk parquet snapshot ({Path(parquet).name})",
        "#",
        "# Instructions: Remove any domains that are out of scope.",
        "# Save this file as domains_approved.txt when done.",
        "# Lines starting with # are ignored.",
        "#",
    ]
    with open(review_file, "w") as f:
        for line in header:
            f.write(line + "\n")
        for domain in all_domains:
            f.write(domain + "\n")
    logger.info(f"Review file written: {review_file}")


def main():
    parser = argparse.ArgumentParser(description="Stage 3 (bulk): Reverse DNS via THC parquet")
    parser.add_argument("--config", default=None)
    parser.add_argument("--run-dir", default=None)
    parser.add_argument("--date", default=None)
    parser.add_argument("--parquet", default=None,
                        help="Path to the decompressed rdns-*.parquet (overrides config)")
    args = parser.parse_args()

    config = load_config(args.config)
    run_dir = Path(args.run_dir) if args.run_dir else get_run_dir(config, args.date)
    success = run(run_dir, config, parquet_override=args.parquet)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
