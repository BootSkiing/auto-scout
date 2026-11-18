#!/usr/bin/env python3
import argparse
import importlib
import json
import sys
import traceback
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.config import load_config, validate_seeds, validate_api_keys, get_run_dir
from lib.logging_setup import setup_logging


STAGE_ORDER = [
    ("s1_seeds", "stages.s1_seeds"),
    ("s2_asn", "stages.s2_asn_discovery"),
    ("s3_rdns", "stages.s3_reverse_dns"),
    ("s4_rwhois", "stages.s4_reverse_whois"),
    ("s5_cleanup", "stages.s5_cleanup"),
    ("s6_subdomains", "stages.s6_subdomain_enum"),
    ("s7_portscan", "stages.s7_port_scan"),
    ("s8_web", "stages.s8_web_analysis"),
    ("s9_extras", "stages.s9_extras"),
]

STAGE_NAMES = [name for name, _ in STAGE_ORDER]


BANNER = r"""
 ______     __  __     ______   ______     ______     ______     ______     __  __     ______
/\  __ \   /\ \/\ \   /\__  _\ /\  __ \   /\  ___\   /\  ___\   /\  __ \   /\ \/\ \   /\__  _\
\ \  __ \  \ \ \_\ \  \/_/\ \/ \ \ \/\ \  \ \___  \  \ \ \____  \ \ \/\ \  \ \ \_\ \  \/_/\ \/
 \ \_\ \_\  \ \_____\    \ \_\  \ \_____\  \/\_____\  \ \_____\  \ \_____\  \ \_____\    \ \_\
  \/_/\/_/   \/_____/     \/_/   \/_____/   \/_____/   \/_____/   \/_____/   \/_____/     \/_/

                          :: external asset enumeration pipeline ::
"""


def print_banner():
    use_color = sys.stdout.isatty()
    cyan = "\033[96m" if use_color else ""
    reset = "\033[0m" if use_color else ""
    print(f"{cyan}{BANNER}{reset}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Auto-Scout - External Asset Enumeration Pipeline",
    )
    parser.add_argument("--config", default=None, help="Path to config file")
    parser.add_argument("--date", default=None, help="Run date override (YYYY-MM-DD)")
    parser.add_argument("--from-stage", dest="from_stage", default=None,
                        choices=STAGE_NAMES, help="Resume from this stage")
    parser.add_argument("--only", default=None,
                        choices=STAGE_NAMES, help="Run only this stage")
    parser.add_argument("--through", default=None,
                        choices=STAGE_NAMES, help="Run stages up through this one")
    parser.add_argument("--review-mode", dest="review_mode", default=None,
                        choices=["halt", "auto"], help="Override review gate behavior")
    parser.add_argument("--rdns-mode", dest="rdns_mode", default="api",
                        choices=["api", "bulk"],
                        help="s3 reverse-DNS backend: 'api' (per-IP THC API, default) "
                             "or 'bulk' (local DuckDB query over THC's bulk parquet; "
                             "requires reverse_dns.bulk.parquet_path)")
    return parser.parse_args()


# s3 reverse-DNS backends selectable via --rdns-mode
RDNS_MODULES = {
    "api": "stages.s3_reverse_dns",
    "bulk": "stages.s3_rdns_bulk",
}


def load_state(run_dir: Path) -> dict:
    state_file = run_dir / "state.json"
    if state_file.exists():
        with open(state_file) as f:
            return json.load(f)
    return {
        "run_date": run_dir.name,
        "started_at": datetime.now().isoformat(),
        "stages": {name: {"status": "not_started"} for name in STAGE_NAMES},
    }


def save_state(run_dir: Path, state: dict):
    state_file = run_dir / "state.json"
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)


def determine_stages(args, state: dict) -> list[tuple[str, str]]:
    if args.only:
        return [(n, m) for n, m in STAGE_ORDER if n == args.only]

    stages = list(STAGE_ORDER)

    if args.through:
        idx = STAGE_NAMES.index(args.through)
        stages = stages[: idx + 1]

    if args.from_stage:
        idx = STAGE_NAMES.index(args.from_stage)
        stages = stages[idx:]

    return stages


def check_review_resumed(stage_name: str, state: dict, run_dir: Path) -> bool:
    stage_state = state["stages"].get(stage_name, {})
    if stage_state.get("status") != "review_needed":
        return True

    review_file = stage_state.get("review_file", "")
    if not review_file:
        return True

    approved_file = review_file.replace("_review.", "_approved.")
    if (run_dir / approved_file).exists():
        return True

    return False


def main():
    print_banner()
    args = parse_args()
    config = load_config(args.config)

    if args.review_mode:
        config["review"]["mode"] = args.review_mode

    run_dir = get_run_dir(config, args.date)
    state = load_state(run_dir)
    logger = setup_logging(run_dir, "orchestrator")

    logger.info(f"Run directory: {run_dir}")

    seed_errors = validate_seeds(config)
    if seed_errors and not (args.only and args.only != "s1_seeds"):
        for err in seed_errors:
            logger.error(err)
        logger.error("Fix seed file issues before running. See seeds/ directory.")
        sys.exit(1)

    stages_to_run = determine_stages(args, state)

    # Select the s3 reverse-DNS backend (api vs bulk).
    rdns_module = RDNS_MODULES[args.rdns_mode]
    stages_to_run = [
        (n, rdns_module if n == "s3_rdns" else m) for n, m in stages_to_run
    ]
    if any(n == "s3_rdns" for n, _ in stages_to_run):
        logger.info(f"s3 reverse-DNS backend: {args.rdns_mode} ({rdns_module})")

    stage_names_to_run = [n for n, _ in stages_to_run]
    api_warnings = validate_api_keys(config, stage_names_to_run)
    for w in api_warnings:
        logger.warning(w)

    for stage_name, module_path in stages_to_run:
        stage_status = state["stages"].get(stage_name, {}).get("status", "not_started")

        if stage_status == "completed" and not args.only:
            logger.info(f"Skipping {stage_name} (already completed)")
            continue

        if stage_status == "review_needed":
            if not check_review_resumed(stage_name, state, run_dir):
                logger.info(f"Stage {stage_name} is waiting for review -- halting")
                logger.info(f"Review file: {state['stages'][stage_name].get('review_file', '?')}")
                break

        logger.info("=" * 60)
        logger.info(f"Starting stage: {stage_name}")

        state["stages"][stage_name] = {"status": "running"}
        save_state(run_dir, state)

        try:
            module = importlib.import_module(module_path)
            success = module.run(run_dir, config)

            if success:
                state["stages"][stage_name] = {
                    "status": "completed",
                    "completed_at": datetime.now().isoformat(),
                }
                logger.info(f"Stage {stage_name} completed")
            else:
                current = state["stages"].get(stage_name, {})
                if current.get("status") != "review_needed":
                    state["stages"][stage_name] = {"status": "halted"}
                save_state(run_dir, state)
                logger.info(f"Pipeline halted at {stage_name}")
                break

        except Exception:
            state["stages"][stage_name] = {
                "status": "failed",
                "error": traceback.format_exc()[-500:],
            }
            save_state(run_dir, state)
            logger.exception(f"Stage {stage_name} failed")
            sys.exit(1)

        save_state(run_dir, state)

    logger.info("")
    logger.info("Pipeline run finished.")
    logger.info(f"State: {run_dir / 'state.json'}")

    completed = sum(1 for s in state["stages"].values() if s.get("status") == "completed")
    total = len(STAGE_NAMES)
    logger.info(f"Stages completed: {completed}/{total}")


if __name__ == "__main__":
    main()
