import pathlib
import sys
from datetime import datetime, date

import yaml


PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_config(config_path: str = None) -> dict:
    if config_path is None:
        config_path = PROJECT_ROOT / "config.yaml"
    else:
        config_path = pathlib.Path(config_path)
        if not config_path.is_absolute():
            config_path = PROJECT_ROOT / config_path

    if not config_path.exists():
        print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    with open(config_path) as f:
        config = yaml.safe_load(f)

    return config


def validate_seeds(config: dict) -> tuple[list[str], list[str]]:
    """Return (errors, warnings).

    corporations and domains are required (missing/empty is an error). The whois
    and out_of_scope lists are optional (missing is only a warning), matching how
    stage 1 treats them.
    """
    errors = []
    warnings = []
    seeds = config.get("seeds", {})

    for key in ("corporations", "domains"):
        path = PROJECT_ROOT / seeds.get(key, "")
        if not path.exists():
            errors.append(f"Required seed file missing: {path}")
        elif path.stat().st_size == 0:
            errors.append(f"Required seed file is empty: {path}")

    for key in ("whois_names", "whois_orgs", "whois_emails", "out_of_scope_domains",
                "out_of_scope_terms", "out_of_scope_asns"):
        path = PROJECT_ROOT / seeds.get(key, "")
        if not path.exists():
            warnings.append(f"Optional seed file missing: {path}")

    return errors, warnings


def validate_api_keys(config: dict, stages: list[str]) -> list[str]:
    warnings = []
    keys = config.get("api_keys", {})

    if "s4_rwhois" in stages and not keys.get("whoxy"):
        warnings.append("Whoxy API key not set -- stage 4 (reverse WHOIS) will fail")

    return warnings


def get_run_dir(config: dict, date_override: str = None) -> pathlib.Path:
    base = PROJECT_ROOT / config.get("output", {}).get("base_dir", "runs")
    if date_override:
        run_date = date_override
    else:
        run_date = date.today().isoformat()

    run_dir = base / run_date
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def get_stage_dir(run_dir: pathlib.Path, stage_name: str) -> pathlib.Path:
    stage_dir = run_dir / stage_name
    stage_dir.mkdir(parents=True, exist_ok=True)
    return stage_dir


def resolve_seed_path(config: dict, key: str) -> pathlib.Path:
    return PROJECT_ROOT / config["seeds"][key]
