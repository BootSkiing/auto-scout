import json
import logging
import shutil
from pathlib import Path


def review_gate(
    stage_name: str,
    review_file: Path,
    approved_file: Path,
    run_dir: Path,
    config: dict,
    logger: logging.Logger,
) -> bool:
    mode = config.get("review", {}).get("mode", "halt")

    if approved_file.exists():
        logger.info(f"Found existing approved file: {approved_file.name} -- skipping review")
        return True

    if not review_file.exists():
        logger.error(f"Review file does not exist: {review_file}")
        return False

    if mode == "auto":
        logger.info(f"Auto-approving review file: {review_file.name}")
        shutil.copy2(review_file, approved_file)
        return True

    # halt mode: update state and stop
    _set_review_needed(run_dir, stage_name, review_file)

    logger.info("")
    logger.info("=" * 60)
    logger.info("REVIEW REQUIRED")
    logger.info(f"  Stage: {stage_name}")
    logger.info(f"  Review file: {review_file}")
    logger.info("")
    logger.info("Instructions:")
    logger.info(f"  1. Open and review: {review_file}")
    logger.info(f"  2. Save approved version as: {approved_file}")
    logger.info("  3. Re-run the pipeline to continue")
    logger.info("=" * 60)
    logger.info("")

    return False


def _set_review_needed(run_dir: Path, stage_name: str, review_file: Path):
    state_file = run_dir / "state.json"
    if state_file.exists():
        with open(state_file) as f:
            state = json.load(f)
    else:
        state = {"stages": {}}

    state["stages"][stage_name] = {
        "status": "review_needed",
        "review_file": str(review_file.relative_to(run_dir)),
    }

    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)
