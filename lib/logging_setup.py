import logging
import pathlib
import sys


_file_handler = None


def setup_logging(run_dir: pathlib.Path, stage_name: str) -> logging.Logger:
    global _file_handler

    logger = logging.getLogger(f"edge.{stage_name}")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.INFO)
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)

    if _file_handler is None:
        log_file = run_dir / "run.log"
        _file_handler = logging.FileHandler(log_file, mode="a")
        _file_handler.setLevel(logging.DEBUG)
        _file_handler.setFormatter(formatter)

    logger.addHandler(_file_handler)

    return logger
