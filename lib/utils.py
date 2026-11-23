import ipaddress
import json
import logging
import re
import subprocess
import time
from functools import wraps
from pathlib import Path

import requests


def read_lines(filepath: str | Path) -> list[str]:
    filepath = Path(filepath)
    if not filepath.exists():
        return []
    lines = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
    return lines


def write_lines(filepath: str | Path, lines: list[str]):
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w") as f:
        for line in lines:
            f.write(line + "\n")


def normalize_to_24(cidr: str) -> list[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    if network.prefixlen >= 24:
        return [str(network)]
    return [str(subnet) for subnet in network.subnets(new_prefix=24)]


def expand_cidr_to_ips(cidr: str) -> list[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in network.hosts()]


def deduplicate_domains(domains: list[str]) -> list[str]:
    seen = set()
    result = []
    for d in domains:
        d = d.lower().strip().rstrip(".")
        if d and d not in seen:
            seen.add(d)
            result.append(d)
    result.sort()
    return result


def has_underscore_label(hostname: str) -> bool:
    """True if any dot-separated label of the hostname starts with '_'.

    Underscore-prefixed labels (RFC 8552) carry service metadata, not hosts:
    _dmarc, _domainkey, _acme-challenge, _mta-sts, and SRV names like
    _sip._tcp all resolve to TXT/SRV records rather than to an address. The
    token "_wildcard" is also how some certificate-transparency tooling renders
    the "*" of a wildcard certificate (*.example.com -> _wildcard.example.com).
    None of these are valid port-scan targets, so they should be filtered out
    before the resolution gate in stage 7.
    """
    return any(label.startswith("_") for label in hostname.split("."))


def normalize_asn(value: str) -> str:
    """Normalize an ASN string to its bare numeric form.

    Accepts "AS1234", "as1234", or "1234" and returns "1234".
    """
    value = value.strip().lower()
    if value.startswith("as"):
        value = value[2:]
    return value.strip()


def matches_exclusion(domain: str, patterns: list[str]) -> bool:
    domain = domain.lower()
    for pattern in patterns:
        if re.search(pattern, domain, re.IGNORECASE):
            return True
    return False


def filter_excluded(domains: list[str], patterns: list[str]) -> tuple[list[str], list[str]]:
    kept = []
    removed = []
    for d in domains:
        if matches_exclusion(d, patterns):
            removed.append(d)
        else:
            kept.append(d)
    return kept, removed


def load_json(filepath: str | Path) -> dict | list:
    with open(filepath) as f:
        return json.load(f)


def save_json(filepath: str | Path, data: dict | list):
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)


def run_command(
    cmd: list[str],
    timeout: int = None,
    cwd: str = None,
    logger: logging.Logger = None,
) -> subprocess.CompletedProcess:
    if logger:
        logger.debug(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired as e:
        # Never let a timeout propagate and abort the whole pipeline. Return a
        # synthetic non-zero result so callers' returncode checks handle it,
        # preserving any partial stdout captured before the kill.
        msg = f"Command timed out after {timeout}s: {' '.join(cmd)}"
        if logger:
            logger.error(msg)
        partial = e.stdout
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        return subprocess.CompletedProcess(cmd, 124, partial or "", msg)
    except FileNotFoundError:
        # Missing binary: treat as a failed command, not a crash.
        msg = f"Command not found: {cmd[0]}"
        if logger:
            logger.error(msg)
        return subprocess.CompletedProcess(cmd, 127, "", msg)
    if logger and result.returncode != 0:
        logger.error(f"Command failed (exit {result.returncode}): {' '.join(cmd)}")
        if result.stderr:
            logger.error(f"stderr: {result.stderr[:1000]}")
    return result


def retry(max_attempts=3, backoff_base=2, exceptions=(requests.RequestException,)):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = kwargs.get("logger") or logging.getLogger("edge")
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    if attempt == max_attempts:
                        logger.error(f"{func.__name__} failed after {max_attempts} attempts: {e}")
                        raise
                    delay = backoff_base ** attempt
                    logger.warning(f"{func.__name__} attempt {attempt} failed: {e}. Retrying in {delay}s...")
                    time.sleep(delay)
        return wrapper
    return decorator
