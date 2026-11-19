#!/usr/bin/env python3
"""
Stage 2: ASN Discovery
Downloads asndb.network datasets, searches for corporation name matches,
extracts CIDR prefixes for matched ASNs.
"""
import argparse
import os
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.config import load_config, get_run_dir, get_stage_dir, resolve_seed_path, PROJECT_ROOT
from lib.logging_setup import setup_logging
from lib.review_gate import review_gate
from lib.utils import read_lines, write_lines, save_json, load_json
from lib.scope import Scope


def _get_cache_dir(config: dict) -> Path:
    cache_dir = PROJECT_ROOT / config.get("asn_discovery", {}).get("cache_dir", ".cache/asndb")
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _download_if_stale(url: str, dest: Path, max_age_hours: int, logger) -> bool:
    if dest.exists():
        age_hours = (time.time() - dest.stat().st_mtime) / 3600
        if age_hours < max_age_hours:
            logger.info(f"Using cached {dest.name} (age: {age_hours:.1f}h)")
            return True

    logger.info(f"Downloading {url}...")
    try:
        resp = requests.get(url, timeout=120, stream=True)
        resp.raise_for_status()
        with open(dest, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        logger.info(f"Downloaded {dest.name} ({dest.stat().st_size / 1024 / 1024:.1f} MB)")
        return True
    except requests.RequestException as e:
        logger.error(f"Failed to download {url}: {e}")
        return False


def _load_asn_json(path: Path) -> dict[str, str]:
    return load_json(path)


def _load_ip_dat(path: Path) -> list[tuple[str, str]]:
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                cidr = parts[0].strip()
                asn = parts[1].strip()
                entries.append((cidr, asn))
    return entries


def _search_asns(
    asn_data: dict[str, str],
    corporation_names: list[str],
    logger,
) -> list[dict]:
    results = []
    seen_asns = set()

    for corp in corporation_names:
        corp_lower = corp.lower()
        for asn_num, description in asn_data.items():
            if asn_num in seen_asns:
                continue
            if corp_lower in description.lower():
                seen_asns.add(asn_num)
                results.append({
                    "asn": asn_num,
                    "description": description,
                    "matched_corporation": corp,
                    "include": True,
                })

    logger.info(
        f"Found {len(results)} unique ASNs matching {len(corporation_names)} corporation names"
    )
    return results


def _extract_prefixes_for_asns(ip_dat: list[tuple[str, str]], approved_asns: set[str]) -> dict[str, list[str]]:
    prefixes = {}
    for cidr, asn in ip_dat:
        if asn in approved_asns:
            prefixes.setdefault(asn, []).append(cidr)
    return prefixes


def run(run_dir: Path, config: dict) -> bool:
    logger = setup_logging(run_dir, "s2_asn")
    stage_dir = get_stage_dir(run_dir, "s2_asn")
    asn_config = config.get("asn_discovery", {})

    cache_dir = _get_cache_dir(config)
    max_age = asn_config.get("cache_max_age_hours", 24)

    asn_json_path = cache_dir / "asn.json"
    ip_dat_path = cache_dir / "ip.dat"

    approved_file = stage_dir / "asns_approved.json"
    ip_ranges_file = stage_dir / "ip_ranges.txt"

    # If we already have approved ASNs and ip_ranges, we're done
    if approved_file.exists() and ip_ranges_file.exists():
        logger.info("ASN discovery already completed (approved file + ip_ranges exist)")
        return True

    # If we have an approved file but no ip_ranges, extract them
    if approved_file.exists():
        logger.info("Found approved file, extracting IP ranges...")
        return _extract_and_write_ranges(approved_file, ip_dat_path, cache_dir, asn_config, stage_dir, logger)

    # Download datasets
    asn_json_url = asn_config.get("asn_json_url", "https://asndb.network/get/latest/asn.json")
    ip_dat_url = asn_config.get("ip_dat_url", "https://asndb.network/get/latest/ip.dat")

    if not _download_if_stale(asn_json_url, asn_json_path, max_age, logger):
        return False
    if not _download_if_stale(ip_dat_url, ip_dat_path, max_age, logger):
        return False

    # Load and search
    logger.info("Loading ASN database...")
    asn_data = _load_asn_json(asn_json_path)
    logger.info(f"Loaded {len(asn_data)} ASN entries")

    scope = Scope(config)
    corporations = read_lines(resolve_seed_path(config, "corporations"))

    # Pre-filter: drop out-of-scope corporation terms before searching the ASN DB
    corporations, removed_terms = scope.filter_terms(corporations)
    scope.record(stage_dir, "terms", "pre", removed_terms, logger)

    asn_results = _search_asns(asn_data, corporations, logger)

    # Post-filter: remove out-of-scope ASNs before the review gate so they never
    # reach the reviewer and never get IP prefixes extracted.
    asn_results, removed_asns = scope.filter_asns(asn_results)
    scope.record(stage_dir, "asns", "post", removed_asns, logger)

    if not asn_results:
        logger.warning("No ASNs found matching any corporation names")
        write_lines(ip_ranges_file, [])
        return True

    # Load IP data to add prefix counts to review file
    logger.info("Loading IP prefix database...")
    ip_dat = _load_ip_dat(ip_dat_path)
    logger.info(f"Loaded {len(ip_dat)} prefix entries")

    all_asn_nums = {r["asn"] for r in asn_results}
    prefix_map = _extract_prefixes_for_asns(ip_dat, all_asn_nums)

    for r in asn_results:
        prefixes = prefix_map.get(r["asn"], [])
        r["prefix_count"] = len(prefixes)
        r["sample_prefixes"] = prefixes[:5]

    # Write review file
    review_data = {
        "_instructions": (
            "Review the ASNs below. Set 'include' to false for any that are out of scope. "
            "Save this file as asns_approved.json when done."
        ),
        "asns": sorted(asn_results, key=lambda x: x["matched_corporation"]),
    }

    review_file = stage_dir / "asns_review.json"
    save_json(review_file, review_data)
    save_json(stage_dir / "asns_raw.json", asn_results)

    logger.info(f"Review file written with {len(asn_results)} ASNs")

    # Review gate
    if not review_gate("s2_asn", review_file, approved_file, run_dir, config, logger):
        return False

    return _extract_and_write_ranges(approved_file, ip_dat_path, cache_dir, asn_config, stage_dir, logger)


def _extract_and_write_ranges(
    approved_file: Path, ip_dat_path: Path, cache_dir: Path,
    asn_config: dict, stage_dir: Path, logger,
) -> bool:
    approved_data = load_json(approved_file)
    approved_asns = set()
    for entry in approved_data.get("asns", []):
        if entry.get("include", True):
            approved_asns.add(str(entry["asn"]))

    logger.info(f"Approved ASNs: {len(approved_asns)}")

    if not ip_dat_path.exists():
        ip_dat_url = asn_config.get("ip_dat_url", "https://asndb.network/get/latest/ip.dat")
        if not _download_if_stale(ip_dat_url, ip_dat_path, 24, logger):
            return False

    ip_dat = _load_ip_dat(ip_dat_path)
    prefix_map = _extract_prefixes_for_asns(ip_dat, approved_asns)

    all_ranges = []
    for asn, prefixes in prefix_map.items():
        all_ranges.extend(prefixes)

    all_ranges = sorted(set(all_ranges))
    ip_ranges_file = stage_dir / "ip_ranges.txt"
    write_lines(ip_ranges_file, all_ranges)
    logger.info(f"Wrote {len(all_ranges)} CIDR ranges to {ip_ranges_file.name}")

    return True


def main():
    parser = argparse.ArgumentParser(description="Stage 2: ASN Discovery")
    parser.add_argument("--config", default=None)
    parser.add_argument("--run-dir", default=None)
    parser.add_argument("--date", default=None)
    args = parser.parse_args()

    config = load_config(args.config)
    run_dir = Path(args.run_dir) if args.run_dir else get_run_dir(config, args.date)
    success = run(run_dir, config)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
