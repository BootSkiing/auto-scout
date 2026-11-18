#!/usr/bin/env python3
"""
Stage 9: Extras
DNS security checks (SPF/DMARC/DKIM) and Google dork generation.
"""
import argparse
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.config import load_config, get_run_dir, get_stage_dir, resolve_seed_path
from lib.logging_setup import setup_logging
from lib.utils import read_lines, write_lines, save_json, run_command


def _dig_txt(domain: str, timeout: int = 5) -> list[str]:
    result = run_command(["dig", "+short", "TXT", domain], timeout=timeout)
    if result.returncode != 0:
        return []
    records = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip().strip('"')
        if line:
            records.append(line)
    return records


def _check_spf(domain: str) -> dict:
    records = _dig_txt(domain)
    spf_records = [r for r in records if r.startswith("v=spf1")]

    result = {"domain": domain, "has_spf": bool(spf_records), "spf_record": None, "issues": []}

    if not spf_records:
        result["issues"].append("No SPF record found")
        return result

    spf = spf_records[0]
    result["spf_record"] = spf

    if "+all" in spf:
        result["issues"].append("SPF uses +all (allows any sender)")
    elif "~all" in spf:
        result["issues"].append("SPF uses ~all (softfail, permissive)")
    elif "?all" in spf:
        result["issues"].append("SPF uses ?all (neutral, no enforcement)")

    return result


def _check_dmarc(domain: str) -> dict:
    records = _dig_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]

    result = {"domain": domain, "has_dmarc": bool(dmarc_records), "dmarc_record": None, "issues": []}

    if not dmarc_records:
        result["issues"].append("No DMARC record found")
        return result

    dmarc = dmarc_records[0]
    result["dmarc_record"] = dmarc

    policy_match = re.search(r"p=(\w+)", dmarc)
    if policy_match:
        policy = policy_match.group(1).lower()
        if policy == "none":
            result["issues"].append("DMARC policy is p=none (monitoring only, no enforcement)")

    return result


def _check_dkim(domain: str, selectors: list[str]) -> dict:
    result = {"domain": domain, "has_dkim": False, "selectors_found": [], "issues": []}

    for selector in selectors:
        records = _dig_txt(f"{selector}._domainkey.{domain}")
        dkim_records = [r for r in records if "DKIM" in r.upper() or "p=" in r]
        if dkim_records:
            result["has_dkim"] = True
            result["selectors_found"].append(selector)

    if not result["has_dkim"]:
        result["issues"].append(f"No DKIM records found (tried selectors: {', '.join(selectors)})")

    return result


def _check_dns_security(domain: str, selectors: list[str]) -> dict:
    spf = _check_spf(domain)
    dmarc = _check_dmarc(domain)
    dkim = _check_dkim(domain, selectors)

    all_issues = spf["issues"] + dmarc["issues"] + dkim["issues"]

    return {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "total_issues": len(all_issues),
        "all_issues": all_issues,
    }


def _run_dns_security(domains: list[str], config: dict, stage_dir: Path, logger):
    extras_config = config.get("extras", {})
    selectors = extras_config.get("dkim_selectors", ["google", "default", "selector1", "selector2", "k1"])

    logger.info(f"Checking DNS security for {len(domains)} domains...")

    results = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_check_dns_security, d, selectors): d for d in domains}
        done = 0
        for future in as_completed(futures):
            done += 1
            result = future.result()
            results.append(result)
            if done % 50 == 0:
                logger.info(f"DNS security progress: {done}/{len(domains)}")

    results.sort(key=lambda x: x["domain"])
    save_json(stage_dir / "dns_security.json", results)

    # Summary
    no_spf = sum(1 for r in results if not r["spf"]["has_spf"])
    no_dmarc = sum(1 for r in results if not r["dmarc"]["has_dmarc"])
    no_dkim = sum(1 for r in results if not r["dkim"]["has_dkim"])
    with_issues = sum(1 for r in results if r["total_issues"] > 0)

    logger.info(f"DNS security summary:")
    logger.info(f"  Domains checked: {len(results)}")
    logger.info(f"  Missing SPF: {no_spf}")
    logger.info(f"  Missing DMARC: {no_dmarc}")
    logger.info(f"  Missing DKIM: {no_dkim}")
    logger.info(f"  Domains with issues: {with_issues}")


def _generate_dorks(corporations: list[str], domains: list[str], stage_dir: Path, logger):
    dorks = []

    for domain in domains:
        dorks.extend([
            f'site:{domain} filetype:pdf',
            f'site:{domain} filetype:xlsx OR filetype:csv',
            f'site:{domain} filetype:doc OR filetype:docx',
            f'site:{domain} inurl:admin OR inurl:login',
            f'site:{domain} intitle:"index of"',
            f'site:{domain} ext:sql OR ext:bak OR ext:log',
            f'site:{domain} ext:conf OR ext:env OR ext:ini',
        ])

    for corp in corporations:
        dorks.extend([
            f'"{corp}" filetype:pdf confidential',
            f'"{corp}" filetype:xlsx OR filetype:csv',
            f'"{corp}" inurl:login',
        ])

    write_lines(stage_dir / "dorks.txt", dorks)
    logger.info(f"Generated {len(dorks)} Google dork queries")


def run(run_dir: Path, config: dict) -> bool:
    logger = setup_logging(run_dir, "s9_extras")
    stage_dir = get_stage_dir(run_dir, "s9_extras")
    extras_config = config.get("extras", {})

    # Load domains
    domains_file = run_dir / "s5_cleanup" / "domains_final.txt"
    domains = read_lines(domains_file) if domains_file.exists() else []
    corporations = read_lines(resolve_seed_path(config, "corporations"))

    if extras_config.get("dns_security", True) and domains:
        dns_out = stage_dir / "dns_security.json"
        if dns_out.exists():
            logger.info("DNS security check already completed")
        else:
            _run_dns_security(domains, config, stage_dir, logger)

    if extras_config.get("google_dorks", True) and (domains or corporations):
        dorks_out = stage_dir / "dorks.txt"
        if dorks_out.exists():
            logger.info("Google dorks already generated")
        else:
            _generate_dorks(corporations, domains, stage_dir, logger)

    return True


def main():
    parser = argparse.ArgumentParser(description="Stage 9: Extras")
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
