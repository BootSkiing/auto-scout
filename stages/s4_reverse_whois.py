#!/usr/bin/env python3
"""
Stage 4: Reverse WHOIS
Queries Whoxy API for domains using registrant name, company, and email seeds.
"""
import argparse
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.config import load_config, get_run_dir, get_stage_dir, resolve_seed_path
from lib.logging_setup import setup_logging
from lib.review_gate import review_gate
from lib.utils import (
    read_lines, write_lines, save_json, load_json,
    deduplicate_domains, filter_excluded,
    clean_stage_dir,
)
from lib.scope import Scope


def _check_balance(api_key: str, base_url: str, logger) -> int | None:
    try:
        resp = requests.get(
            base_url,
            params={"key": api_key, "account": "balance"},
            timeout=15,
        )
        data = resp.json()
        if data.get("status") == 1:
            balance = data.get("reverse_whois_balance", 0)
            logger.info(f"Whoxy reverse WHOIS balance: {balance} credits")
            return balance
    except Exception as e:
        logger.warning(f"Could not check Whoxy balance: {e}")
    return None


def _reverse_whois_query(
    api_key: str, base_url: str, search_type: str, value: str,
    mode: str, delay: float, logger,
) -> list[str]:
    domains = []
    page = 1

    while True:
        params = {
            "key": api_key,
            "reverse": "whois",
            search_type: value,
            "mode": mode,
            "page": page,
        }

        try:
            resp = requests.get(base_url, params=params, timeout=30)
            data = resp.json()
        except Exception as e:
            logger.error(f"Whoxy API error for {search_type}={value} page {page}: {e}")
            break

        if data.get("status") != 1:
            reason = data.get("status_reason", "Unknown error")
            if "no results" in reason.lower() or "empty" in reason.lower():
                break
            logger.warning(f"Whoxy API: {reason} (search_type={search_type}, value={value})")
            break

        search_result = data.get("search_result", [])
        if not search_result:
            break

        for entry in search_result:
            domain = entry.get("domain_name", "").strip().lower()
            if domain:
                domains.append(domain)

        total_pages = data.get("total_pages", 1)
        if page >= total_pages:
            break

        page += 1
        time.sleep(delay)

    time.sleep(delay)
    return domains


def run(run_dir: Path, config: dict) -> bool:
    logger = setup_logging(run_dir, "s4_rwhois")
    stage_dir = get_stage_dir(run_dir, "s4_rwhois")

    approved_file = stage_dir / "domains_approved.txt"
    if approved_file.exists():
        logger.info("Reverse WHOIS already completed (approved file exists)")
        return True

    # Clear regenerated outputs from a prior run (approved file preserved).
    clean_stage_dir(stage_dir, logger=logger)

    rwhois_config = config.get("reverse_whois", {})
    api_key = config.get("api_keys", {}).get("whoxy", "")
    if not api_key:
        logger.error("Whoxy API key not configured. Set api_keys.whoxy in config.yaml")
        return False

    base_url = rwhois_config.get("whoxy_base_url", "https://api.whoxy.com")
    mode = rwhois_config.get("mode", "micro")
    delay = rwhois_config.get("request_delay_seconds", 1.0)

    _check_balance(api_key, base_url, logger)

    # Collect search terms from all three seed types
    search_jobs = []

    names = read_lines(resolve_seed_path(config, "whois_names"))
    for name in names:
        search_jobs.append(("name", name))

    orgs = read_lines(resolve_seed_path(config, "whois_orgs"))
    for org in orgs:
        search_jobs.append(("company", org))

    emails = read_lines(resolve_seed_path(config, "whois_emails"))
    for email in emails:
        search_jobs.append(("email", email))

    # Pre-filter: drop out-of-scope search terms before querying (saves API calls)
    scope = Scope(config)
    search_jobs, removed_terms = scope.filter_terms(search_jobs, key=lambda j: j[1])
    scope.record(stage_dir, "terms", "pre", removed_terms, logger)

    if not search_jobs:
        logger.warning("No WHOIS search terms found in seed files")
        write_lines(stage_dir / "domains_review.txt", [])
        write_lines(approved_file, [])
        return True

    logger.info(f"Reverse WHOIS searches: {len(names)} names, {len(orgs)} companies, {len(emails)} emails")

    all_domains = []
    raw_results = {}

    for search_type, value in search_jobs:
        logger.info(f"Querying: {search_type}={value}")
        domains = _reverse_whois_query(api_key, base_url, search_type, value, mode, delay, logger)
        logger.info(f"  Found {len(domains)} domains")
        all_domains.extend(domains)
        raw_results[f"{search_type}:{value}"] = domains

    save_json(stage_dir / "rwhois_raw.json", raw_results)

    all_domains = deduplicate_domains(all_domains)
    logger.info(f"Total unique domains: {len(all_domains)}")

    # Pre-filter exclusions (regex cleanup: Akamai/CloudFront junk, etc.)
    exclusion_patterns = config.get("cleanup", {}).get("excluded_domain_patterns", [])
    if exclusion_patterns:
        all_domains, removed = filter_excluded(all_domains, exclusion_patterns)
        if removed:
            logger.info(f"Pre-filtered {len(removed)} domains matching exclusion patterns")

    # Remove out-of-scope domains before the review gate
    all_domains, removed_oos = scope.filter_domains(all_domains)
    scope.record(stage_dir, "domains", "post", removed_oos, logger)

    # Write review file
    review_file = stage_dir / "domains_review.txt"
    header = [
        "# REVIEW FILE - Stage 4: Reverse WHOIS domains",
        f"# Total domains: {len(all_domains)}",
        f"# Sources: {len(names)} names, {len(orgs)} companies, {len(emails)} emails",
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

    _check_balance(api_key, base_url, logger)

    if not review_gate("s4_rwhois", review_file, approved_file, run_dir, config, logger):
        return False

    return True


def main():
    parser = argparse.ArgumentParser(description="Stage 4: Reverse WHOIS")
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
