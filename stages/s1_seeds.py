#!/usr/bin/env python3
"""
Stage 1: Seed Validation
Validates seed files exist and are non-empty, copies them into the run
directory for reproducibility.
"""
import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.config import load_config, get_run_dir, resolve_seed_path, PROJECT_ROOT
from lib.logging_setup import setup_logging
from lib.utils import read_lines


def run(run_dir: Path, config: dict) -> bool:
    logger = setup_logging(run_dir, "s1_seeds")

    seeds_snapshot = run_dir / "seeds"
    seeds_snapshot.mkdir(parents=True, exist_ok=True)

    seed_keys = ["corporations", "domains", "whois_names", "whois_orgs", "whois_emails",
                 "out_of_scope_domains", "out_of_scope_terms", "out_of_scope_asns"]
    counts = {}
    errors = []

    for key in seed_keys:
        src = resolve_seed_path(config, key)
        if not src.exists():
            if key in ("corporations", "domains"):
                errors.append(f"Required seed file missing: {src}")
            else:
                logger.warning(f"Optional seed file missing: {src}")
            continue

        lines = read_lines(src)
        counts[key] = len(lines)

        if key in ("corporations", "domains") and len(lines) == 0:
            errors.append(f"Required seed file is empty: {src}")
            continue

        shutil.copy2(src, seeds_snapshot / src.name)

    if errors:
        for e in errors:
            logger.error(e)
        return False

    logger.info("Seed file summary:")
    for key, count in counts.items():
        logger.info(f"  {key}: {count} entries")
    logger.info(f"Seed files copied to {seeds_snapshot}")

    return True


def main():
    parser = argparse.ArgumentParser(description="Stage 1: Seed Validation")
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
