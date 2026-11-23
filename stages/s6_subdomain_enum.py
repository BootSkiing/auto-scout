#!/usr/bin/env python3
"""
Stage 6: Subdomain Enumeration
Runs bbot passive subdomain enumeration against the cleaned domain list.
"""
import argparse
import glob
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.config import load_config, get_run_dir, get_stage_dir
from lib.logging_setup import setup_logging
from lib.utils import read_lines, write_lines, deduplicate_domains, run_command, clean_stage_dir
from lib.scope import Scope


def _build_bbot_cmd(
    targets: list[str], output_dir: Path, scan_name: str,
    config: dict, logger,
) -> list[str]:
    sub_config = config.get("subdomain_enum", {})
    api_keys = config.get("api_keys", {})

    cmd = ["bbot"]

    # Targets
    cmd.extend(["-t"] + targets)

    # Flags
    flags = sub_config.get("bbot_flags", ["passive", "safe", "subdomain-enum"])
    if flags:
        cmd.extend(["-f"] + flags)

    # Exclude flags
    exclude_flags = sub_config.get("bbot_exclude_flags", ["active"])
    if exclude_flags:
        cmd.extend(["-rf"] + exclude_flags)

    # Exclude modules. Start from the user's configured list, then default-exclude
    # modules that are slow, rate-limited time-sinks relative to their yield here:
    #   - wayback: archive.org's CDX API is slow and rate-limited (~60 req/min,
    #     120s sleeps on 429) and returns very few subdomains per batch. It finds
    #     unique archive-sourced subdomains, so re-enable with
    #     subdomain_enum.enable_wayback: true if you want that coverage.
    #   - certspotter: SSLMate rate-limits it into multi-minute stalls when
    #     unauthenticated, and its CT data is already covered by crt/crt_db/myssl.
    #     Auto-enabled only when api_keys.sslmate unlocks its fast paginated path.
    exclude_modules = list(sub_config.get("bbot_exclude_modules", []))
    default_excludes = []
    if not sub_config.get("enable_wayback", False):
        default_excludes.append("wayback")
    if not api_keys.get("sslmate"):
        default_excludes.append("certspotter")
    for module in default_excludes:
        if module not in exclude_modules:
            exclude_modules.append(module)
    if exclude_modules:
        cmd.extend(["-em"] + exclude_modules)

    # Output modules
    cmd.extend(["-om", "subdomains", "csv", "json"])

    # Output directory and scan name
    cmd.extend(["-o", str(output_dir)])
    cmd.extend(["-n", scan_name])

    # API key configs
    config_args = []
    key_map = {
        "shodan": "modules.shodan_dns.api_key",
        "securitytrails": "modules.securitytrails.api_key",
        "virustotal": "modules.virustotal.api_key",
        "github": "modules.github_codesearch.api_key",
        "chaos": "modules.chaos.api_key",
        "sslmate": "modules.certspotter.api_key",
    }
    for key_name, config_path in key_map.items():
        key_value = api_keys.get(key_name, "")
        if key_value:
            config_args.append(f"{config_path}={key_value}")

    if api_keys.get("censys_id") and api_keys.get("censys_secret"):
        config_args.append(f"modules.censys_dns.api_key={api_keys['censys_id']}:{api_keys['censys_secret']}")

    if config_args:
        cmd.extend(["-c"] + config_args)

    # Non-interactive
    cmd.extend(["-y", "--force"])

    return cmd


def _collect_subdomains(output_dir: Path, logger) -> list[str]:
    subdomains = []

    # Check bbot subdomains output files
    for subdomains_file in output_dir.rglob("subdomains.txt"):
        lines = read_lines(subdomains_file)
        subdomains.extend(lines)
        logger.debug(f"Read {len(lines)} subdomains from {subdomains_file}")

    # Also check CSV output for DNS_NAME events
    for csv_file in output_dir.rglob("output.csv"):
        try:
            with open(csv_file) as f:
                header = f.readline().strip().split(",")
                if "Event data" in header and "Event type" in header:
                    data_idx = header.index("Event data")
                    type_idx = header.index("Event type")
                    for line in f:
                        parts = line.strip().split(",")
                        if len(parts) > max(data_idx, type_idx):
                            if parts[type_idx] == "DNS_NAME":
                                subdomains.append(parts[data_idx].strip())
        except Exception as e:
            logger.debug(f"Error parsing {csv_file}: {e}")

    return subdomains


def run(run_dir: Path, config: dict) -> bool:
    logger = setup_logging(run_dir, "s6_subdomains")
    stage_dir = get_stage_dir(run_dir, "s6_subdomains")

    output_file = stage_dir / "subdomains.txt"
    if output_file.exists():
        existing = read_lines(output_file)
        if existing:
            logger.info(f"Subdomain enum already completed ({len(existing)} subdomains)")
            return True

    # Clear regenerated outputs (including a stale bbot_output/ dir) before rerun.
    clean_stage_dir(stage_dir, logger=logger)

    # Check bbot is available
    result = run_command(["bbot", "--version"], logger=logger)
    if result.returncode != 0:
        logger.error("bbot not found or not working")
        return False

    # Load domains
    domains_file = run_dir / "s5_cleanup" / "domains_final.txt"
    if not domains_file.exists():
        logger.error(f"Missing input: {domains_file}. Run stage 5 first.")
        return False

    domains = read_lines(domains_file)
    if not domains:
        logger.warning("No domains to enumerate")
        write_lines(output_file, [])
        return True

    logger.info(f"Running passive subdomain enumeration against {len(domains)} domains")

    batch_size = config.get("subdomain_enum", {}).get("batch_size", 20)
    timeout_minutes = config.get("subdomain_enum", {}).get("timeout_minutes", 120)
    bbot_output_dir = stage_dir / "bbot_output"
    bbot_output_dir.mkdir(exist_ok=True)

    all_subdomains = []
    batches = [domains[i : i + batch_size] for i in range(0, len(domains), batch_size)]

    for batch_num, batch in enumerate(batches, 1):
        scan_name = f"edge_subdomains_batch_{batch_num:02d}"
        logger.info(f"Batch {batch_num}/{len(batches)}: {len(batch)} domains ({scan_name})")

        cmd = _build_bbot_cmd(batch, bbot_output_dir, scan_name, config, logger)
        logger.debug(f"bbot command: {' '.join(cmd)}")

        # bbot uses a rich terminal UI that hangs when stdout/stderr are captured
        # to pipes, so redirect to log files instead
        bbot_log = stage_dir / f"bbot_{scan_name}.log"
        with open(bbot_log, "w") as log_fh:
            try:
                result = subprocess.run(
                    cmd, stdout=log_fh, stderr=subprocess.STDOUT,
                    timeout=timeout_minutes * 60,
                )
            except subprocess.TimeoutExpired:
                logger.warning(f"bbot batch {batch_num} timed out after {timeout_minutes}m")
                result = None

        if result and result.returncode != 0:
            logger.warning(f"bbot batch {batch_num} exited with code {result.returncode}")

        # Collect results from this batch
        batch_dir = bbot_output_dir / scan_name
        if batch_dir.exists():
            batch_subs = _collect_subdomains(batch_dir, logger)
            logger.info(f"Batch {batch_num}: found {len(batch_subs)} subdomains")
            all_subdomains.extend(batch_subs)

    all_subdomains = deduplicate_domains(all_subdomains)
    logger.info(f"Total unique subdomains: {len(all_subdomains)}")

    # Remove out-of-scope subdomains newly discovered here so they don't flow
    # into port scanning / web analysis. (s6 has no human gate.)
    scope = Scope(config)
    all_subdomains, removed_oos = scope.filter_domains(all_subdomains)
    scope.record(stage_dir, "domains", "post", removed_oos, logger)

    write_lines(output_file, all_subdomains)

    # Also write subdomains grouped by parent domain
    by_parent = {}
    for sub in all_subdomains:
        parts = sub.split(".")
        if len(parts) >= 2:
            parent = ".".join(parts[-2:])
            by_parent.setdefault(parent, []).append(sub)

    from lib.utils import save_json
    save_json(stage_dir / "subdomains_by_domain.json", by_parent)

    return True


def main():
    parser = argparse.ArgumentParser(description="Stage 6: Subdomain Enumeration")
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
