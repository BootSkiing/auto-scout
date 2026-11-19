#!/usr/bin/env python3
"""
Stage 5: Cleanup
Merges domains from stages 3+4 and seeds, deduplicates, removes parked/excluded domains.
"""
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.config import load_config, get_run_dir, get_stage_dir, resolve_seed_path
from lib.logging_setup import setup_logging
from lib.utils import (
    read_lines, write_lines, save_json,
    deduplicate_domains, filter_excluded,
)
from lib.scope import Scope


def _check_parking(domain: str, indicators: list[str], timeout: int) -> dict:
    result = {
        "domain": domain,
        "parked": False,
        "reason": None,
        "http_status": None,
        "error": None,
    }

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; auto-scout/1.0)"},
            )
            result["http_status"] = resp.status_code
            body = resp.text.lower()

            for indicator in indicators:
                if indicator.lower() in body:
                    result["parked"] = True
                    result["reason"] = indicator
                    return result

            return result

        except requests.RequestException:
            continue

    result["error"] = "unreachable"
    return result


def run(run_dir: Path, config: dict) -> bool:
    logger = setup_logging(run_dir, "s5_cleanup")
    stage_dir = get_stage_dir(run_dir, "s5_cleanup")

    final_file = stage_dir / "domains_final.txt"
    if final_file.exists():
        existing = read_lines(final_file)
        if existing:
            logger.info(f"Cleanup already completed ({len(existing)} domains in {final_file.name})")
            return True

    # Collect domains from all sources
    sources = {}

    seed_domains = read_lines(resolve_seed_path(config, "domains"))
    sources["seeds"] = seed_domains

    rdns_file = run_dir / "s3_rdns" / "domains_approved.txt"
    if rdns_file.exists():
        sources["reverse_dns"] = read_lines(rdns_file)
    else:
        logger.warning("No reverse DNS approved domains found")
        sources["reverse_dns"] = []

    rwhois_file = run_dir / "s4_rwhois" / "domains_approved.txt"
    if rwhois_file.exists():
        sources["reverse_whois"] = read_lines(rwhois_file)
    else:
        logger.warning("No reverse WHOIS approved domains found")
        sources["reverse_whois"] = []

    for source, domains in sources.items():
        logger.info(f"Source {source}: {len(domains)} domains")

    # Merge and deduplicate
    all_domains = []
    for domains in sources.values():
        all_domains.extend(domains)

    write_lines(stage_dir / "all_domains_raw.txt", all_domains)

    all_domains = deduplicate_domains(all_domains)
    logger.info(f"After deduplication: {len(all_domains)} unique domains")

    # Apply regex exclusion patterns (cleanup: Akamai/CloudFront junk, etc.)
    exclusion_patterns = config.get("cleanup", {}).get("excluded_domain_patterns", [])
    if exclusion_patterns:
        all_domains, removed = filter_excluded(all_domains, exclusion_patterns)
        logger.info(f"Removed {len(removed)} domains matching exclusion patterns")
        if removed:
            write_lines(stage_dir / "excluded_domains.txt", removed)

    # Remove out-of-scope domains. s5 is the only place seed domains get scope-
    # checked, and the backstop for anything approved upstream before a seed was
    # marked out of scope.
    scope = Scope(config)
    all_domains, removed_oos = scope.filter_domains(all_domains)
    scope.record(stage_dir, "domains", "post", removed_oos, logger)

    write_lines(stage_dir / "domains_deduped.txt", all_domains)

    # Parking page detection
    cleanup_config = config.get("cleanup", {})
    indicators = cleanup_config.get("parking_indicators", [])
    timeout = cleanup_config.get("parking_check_timeout", 5)
    threads = cleanup_config.get("parking_check_threads", 20)

    if indicators and all_domains:
        logger.info(f"Checking {len(all_domains)} domains for parking pages ({threads} threads)...")

        # Suppress InsecureRequestWarning for parking checks
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        parking_results = []
        parked_domains = set()

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(_check_parking, domain, indicators, timeout): domain
                for domain in all_domains
            }
            done = 0
            for future in as_completed(futures):
                done += 1
                result = future.result()
                parking_results.append(result)
                if result["parked"]:
                    parked_domains.add(result["domain"])
                if done % 100 == 0:
                    logger.info(f"Parking check progress: {done}/{len(all_domains)}")

        save_json(stage_dir / "parking_check.json", parking_results)
        logger.info(f"Parked domains detected: {len(parked_domains)}")

        all_domains = [d for d in all_domains if d not in parked_domains]

    write_lines(final_file, all_domains)
    logger.info(f"Final domain list: {len(all_domains)} domains written to {final_file.name}")

    return True


def main():
    parser = argparse.ArgumentParser(description="Stage 5: Cleanup")
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
