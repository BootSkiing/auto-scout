#!/usr/bin/env python3
"""
Stage 3: Reverse DNS
Queries ip.thc.org for domains hosted on each IP from ASN discovery.
Supports resuming from progress checkpoints.
"""
import argparse
import re
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
    normalize_to_24, expand_cidr_to_ips, deduplicate_domains, filter_excluded,
)
from lib.scope import Scope

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _parse_thc_response(text: str) -> dict:
    text = ANSI_ESCAPE.sub("", text)
    lines = text.strip().split("\n")

    metadata = {}
    domains = []
    next_page = None

    for line in lines:
        if line.startswith(";;Next Page:"):
            next_page = line.split(";;Next Page:", 1)[1].strip()
        elif line.startswith(";;Rate Limit:"):
            match = re.search(r"You can make (\d+) requests", line)
            if match:
                metadata["remaining_requests"] = int(match.group(1))
        elif line.startswith(";;Entries:"):
            match = re.search(r"(\d+)/(\d+)", line)
            if match:
                metadata["returned"] = int(match.group(1))
                metadata["total"] = int(match.group(2))
        elif line.startswith(";"):
            continue
        elif line.strip():
            domains.append(line.strip().lower().rstrip("."))

    return {
        "domains": domains,
        "next_page": next_page,
        "metadata": metadata,
    }


def _backoff_seconds(retry_after: str | None, attempt: int, delay: float) -> float:
    """How long to wait before retrying a 429.

    Honors a server-provided Retry-After (seconds) when present; otherwise
    backs off exponentially from the base delay, capped at 60s. THC replenishes
    its token bucket at 0.5/sec, so even one base delay regains a token.
    """
    if retry_after:
        try:
            return max(float(retry_after), delay)
        except (TypeError, ValueError):
            pass
    return min(delay * (2 ** attempt), 60.0)


def _rate_remaining(resp: requests.Response, parsed: dict) -> int | None:
    """Remaining request budget, preferring the authoritative response header
    (present on every response, including 429s) over the body comment line."""
    header = resp.headers.get("X-Ratelimit-Remaining")
    if header is not None:
        try:
            return int(header)
        except ValueError:
            pass
    return parsed.get("metadata", {}).get("remaining_requests")


def _query_thc(
    ip: str, config: dict, session: requests.Session, logger
) -> tuple[list[str], bool]:
    """Query THC for one IP, following pagination.

    Returns (domains, ok). ok is False only when the IP could not be queried
    (persistent 429 or network error after retries); the caller must NOT mark
    such an IP completed, so it is retried on resume. A 404 (no reverse-DNS
    data for the IP) is a genuine, completed query -> ok is True with no domains.
    """
    rd = config.get("reverse_dns", {})
    base_url = rd.get("base_url", "https://ip.thc.org")
    delay = rd.get("request_delay_seconds", 2.0)
    max_retries = rd.get("max_retries_on_429", 6)
    all_domains = []
    url = f"{base_url}/{ip}"

    while url:
        resp = None
        for attempt in range(max_retries + 1):
            try:
                resp = session.get(url, timeout=15)
            except requests.RequestException as e:
                if attempt >= max_retries:
                    logger.debug(f"Network error on {url}, giving up: {e}")
                    return all_domains, False
                time.sleep(_backoff_seconds(None, attempt, delay))
                continue

            if resp.status_code == 429:
                if attempt >= max_retries:
                    logger.warning(f"Persistent 429 for {url}; IP left for retry")
                    return all_domains, False
                wait = _backoff_seconds(resp.headers.get("Retry-After"), attempt, delay)
                logger.debug(f"429 for {url}, waiting {wait:.1f}s (attempt {attempt + 1})")
                time.sleep(wait)
                continue

            if resp.status_code == 404:
                # Genuinely queried; the IP simply has no reverse-DNS entries.
                return all_domains, True

            try:
                resp.raise_for_status()
            except requests.RequestException as e:
                logger.debug(f"Failed to query {url}: {e}")
                return all_domains, False
            break  # 2xx
        else:
            return all_domains, False

        parsed = _parse_thc_response(resp.text)
        all_domains.extend(parsed["domains"])

        remaining = _rate_remaining(resp, parsed)
        if remaining is not None and remaining < 10:
            wait = max(delay * 3, 20)
            logger.warning(f"Rate limit low ({remaining} remaining), waiting {wait}s...")
            time.sleep(wait)
        else:
            time.sleep(delay)

        url = parsed["next_page"]

    return all_domains, True


def _load_progress(stage_dir: Path) -> dict:
    progress_file = stage_dir / "progress.json"
    if progress_file.exists():
        return load_json(progress_file)
    return {"completed_ips": [], "domains_found": {}}


def _save_progress(stage_dir: Path, progress: dict):
    save_json(stage_dir / "progress.json", progress)


def run(run_dir: Path, config: dict) -> bool:
    logger = setup_logging(run_dir, "s3_rdns")
    stage_dir = get_stage_dir(run_dir, "s3_rdns")

    approved_file = stage_dir / "domains_approved.txt"
    if approved_file.exists():
        logger.info("Reverse DNS already completed (approved file exists)")
        return True

    # Load IP ranges from stage 2
    ip_ranges_file = run_dir / "s2_asn" / "ip_ranges.txt"
    if not ip_ranges_file.exists():
        logger.error(f"Missing input: {ip_ranges_file}. Run stage 2 first.")
        return False

    cidrs = read_lines(ip_ranges_file)
    if not cidrs:
        logger.warning("No IP ranges to process")
        write_lines(stage_dir / "domains_review.txt", [])
        write_lines(approved_file, [])
        return True

    # Expand CIDRs to individual IPs for THC queries
    # THC works per-IP, so we need to expand but can skip broadcast/network
    all_ips = []
    for cidr in cidrs:
        subnets = normalize_to_24(cidr)
        for subnet in subnets:
            ips = expand_cidr_to_ips(subnet)
            all_ips.extend(ips)

    all_ips = sorted(set(all_ips))
    logger.info(f"Total IPs to query: {len(all_ips)} (from {len(cidrs)} CIDR ranges)")

    # Load progress for resumability
    progress = _load_progress(stage_dir)
    completed_set = set(progress["completed_ips"])
    remaining_ips = [ip for ip in all_ips if ip not in completed_set]

    if completed_set:
        logger.info(f"Resuming: {len(completed_set)} IPs already completed, {len(remaining_ips)} remaining")

    save_interval = config.get("reverse_dns", {}).get("progress_save_interval", 50)
    session = requests.Session()
    session.headers["User-Agent"] = "auto-scout/1.0"

    domains_found = progress.get("domains_found", {})

    max_consecutive = config.get("reverse_dns", {}).get("max_consecutive_failures", 5)
    consecutive_failures = 0

    for i, ip in enumerate(remaining_ips, 1):
        domains, ok = _query_thc(ip, config, session, logger)

        if not ok:
            # Not successfully queried (persistent rate-limit / network error).
            # Do NOT mark completed, so this IP is retried on the next resume.
            consecutive_failures += 1
            logger.warning(
                f"[{i}/{len(remaining_ips)}] {ip}: not queried "
                f"({consecutive_failures} consecutive failure(s))"
            )
            if consecutive_failures >= max_consecutive:
                logger.error(
                    f"Aborting s3: {consecutive_failures} consecutive IPs failed to "
                    f"query (server rate-limiting or unreachable). Progress saved; "
                    f"re-run this stage to resume from here."
                )
                progress["domains_found"] = domains_found
                _save_progress(stage_dir, progress)
                return False
            continue

        consecutive_failures = 0
        if domains:
            domains_found[ip] = domains
            logger.debug(f"[{i}/{len(remaining_ips)}] {ip}: {len(domains)} domains")
        else:
            logger.debug(f"[{i}/{len(remaining_ips)}] {ip}: no domains")

        progress["completed_ips"].append(ip)

        if i % save_interval == 0:
            progress["domains_found"] = domains_found
            _save_progress(stage_dir, progress)
            total_domains = sum(len(d) for d in domains_found.values())
            logger.info(f"Progress: {len(progress['completed_ips'])}/{len(all_ips)} IPs, {total_domains} domains found")

    # Final save
    progress["domains_found"] = domains_found
    _save_progress(stage_dir, progress)

    # Collect and deduplicate all domains
    all_domains = []
    for ip_domains in domains_found.values():
        all_domains.extend(ip_domains)

    all_domains = deduplicate_domains(all_domains)
    logger.info(f"Total unique domains found: {len(all_domains)}")

    # Save raw results
    save_json(stage_dir / "rdns_raw.json", domains_found)

    # Filter out excluded patterns (regex cleanup: Akamai/CloudFront junk, etc.)
    exclusion_patterns = config.get("cleanup", {}).get("excluded_domain_patterns", [])
    if exclusion_patterns:
        all_domains, removed = filter_excluded(all_domains, exclusion_patterns)
        if removed:
            logger.info(f"Pre-filtered {len(removed)} domains matching exclusion patterns")

    # Remove out-of-scope domains before the review gate
    scope = Scope(config)
    all_domains, removed_oos = scope.filter_domains(all_domains)
    scope.record(stage_dir, "domains", "post", removed_oos, logger)

    # Write review file
    review_file = stage_dir / "domains_review.txt"
    header = [
        "# REVIEW FILE - Stage 3: Reverse DNS domains",
        f"# Total domains: {len(all_domains)}",
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

    if not review_gate("s3_rdns", review_file, approved_file, run_dir, config, logger):
        return False

    return True


def main():
    parser = argparse.ArgumentParser(description="Stage 3: Reverse DNS")
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
