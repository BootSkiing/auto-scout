#!/usr/bin/env python3
"""
Stage 8: Web Analysis
Parses nmap XML for web services and runs gowitness for screenshotting.
"""
import argparse
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.config import load_config, get_run_dir, get_stage_dir
from lib.logging_setup import setup_logging
from lib.utils import read_lines, write_lines, run_command, load_json, clean_stage_dir


def _is_web_service(service_elem, portid: int, fallback_ports: list[int]) -> bool:
    if service_elem is not None:
        name = service_elem.get("name", "").lower()
        product = service_elem.get("product", "").lower()
        # nmap identified the service -- trust it
        if "http" in name:
            return True
        if any(kw in product for kw in ("apache", "nginx", "iis", "lighttpd", "tomcat", "openresty")):
            return True
        # nmap identified a non-http service on this port -- skip it
        if name and "http" not in name:
            return False
    # nmap couldn't fingerprint the service -- fall back to the port list
    return portid in fallback_ports


def _is_ssl(service_elem, portid: int) -> bool:
    if service_elem is not None:
        tunnel = service_elem.get("tunnel", "").lower()
        name = service_elem.get("name", "").lower()
        if "ssl" in tunnel or "tls" in tunnel or "https" in name:
            return True
    return False


def _extract_web_targets(nmap_xml: str, fallback_ports: list[int], ip_hostname_map: dict[str, list[str]], logger) -> list[str]:
    tree = ET.parse(nmap_xml)
    root = tree.getroot()

    urls = []

    for host in root.findall(".//host"):
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host.find("address")
        ip = addr_elem.get("addr", "") if addr_elem is not None else ""

        # Build target list: all known hostnames for this IP, plus nmap's own detection
        targets = list(ip_hostname_map.get(ip, []))
        hostname_elem = host.find(".//hostname")
        nmap_hostname = hostname_elem.get("name", "") if hostname_elem is not None else ""
        if nmap_hostname and nmap_hostname not in targets:
            targets.append(nmap_hostname)
        if not targets:
            targets = [ip]

        for port in host.findall(".//port"):
            state_elem = port.find("state")
            if state_elem is None or "open" not in state_elem.get("state", ""):
                continue

            portid = int(port.get("portid", 0))
            service_elem = port.find("service")

            if not _is_web_service(service_elem, portid, fallback_ports):
                continue

            scheme = "https" if _is_ssl(service_elem, portid) else "http"
            for target in targets:
                if (scheme == "http" and portid == 80) or (scheme == "https" and portid == 443):
                    url = f"{scheme}://{target}"
                else:
                    url = f"{scheme}://{target}:{portid}"
                urls.append(url)

    return sorted(set(urls))


def run(run_dir: Path, config: dict) -> bool:
    logger = setup_logging(run_dir, "s8_web")
    stage_dir = get_stage_dir(run_dir, "s8_web")

    db_file = stage_dir / "gowitness.sqlite3"
    if db_file.exists():
        logger.info("Web analysis already completed (gowitness database exists)")
        return True

    # Clear regenerated outputs (old screenshots/, targets, partial db) before rerun.
    clean_stage_dir(stage_dir, logger=logger)

    nmap_xml = run_dir / "s7_portscan" / "nmap_results.xml"
    if not nmap_xml.exists():
        logger.error(f"Missing input: {nmap_xml}. Run stage 7 first.")
        return False

    if not shutil.which("gowitness"):
        logger.error("gowitness not installed. Run setup.sh or install manually.")
        return False

    web_config = config.get("web_analysis", {})
    http_ports = web_config.get("http_fallback_ports", [80, 443, 8080, 8443, 8000, 8888, 9443])
    threads = web_config.get("gowitness_threads", 10)
    timeout = web_config.get("gowitness_timeout", 15)

    # Load IP-to-hostname mapping from stage 7 so URLs use real domain names
    ip_hostname_map_file = run_dir / "s7_portscan" / "ip_hostname_map.json"
    ip_hostname_map = load_json(ip_hostname_map_file) if ip_hostname_map_file.exists() else {}

    urls = _extract_web_targets(str(nmap_xml), http_ports, ip_hostname_map, logger)
    logger.info(f"Found {len(urls)} web targets from nmap results")

    if not urls:
        logger.warning("No web targets found")
        return True

    targets_file = stage_dir / "web_targets.txt"
    write_lines(targets_file, urls)

    screenshots_dir = stage_dir / "screenshots"
    screenshots_dir.mkdir(exist_ok=True)

    cmd = [
        "gowitness", "scan", "file",
        "--file", str(targets_file),
        "--write-db",
        "--write-db-uri", f"sqlite://{db_file}",
        "--screenshot-path", str(screenshots_dir),
        "--threads", str(threads),
        "--timeout", str(timeout),
    ]

    logger.info(f"Running gowitness ({threads} threads, {timeout}s timeout)...")
    result = run_command(cmd, timeout=3600, logger=logger)

    if result.returncode != 0:
        logger.warning(f"gowitness exited with code {result.returncode}")
        if result.stderr:
            logger.warning(f"stderr: {result.stderr[:500]}")

    if db_file.exists():
        logger.info(f"gowitness database: {db_file}")
        logger.info(f"Screenshots: {screenshots_dir}")
        logger.info("")
        logger.info("To browse results, run:")
        logger.info(f"  gowitness report server --db-uri sqlite://{db_file} --screenshot-path {screenshots_dir}")
    else:
        logger.error("gowitness did not produce a database")
        return False

    return True


def main():
    parser = argparse.ArgumentParser(description="Stage 8: Web Analysis")
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
