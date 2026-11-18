#!/usr/bin/env python3
"""
Stage 7: Port Scanning
masscan for alive host discovery, nmap for service fingerprinting,
XML-to-Excel conversion.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.config import load_config, get_run_dir, get_stage_dir
from lib.logging_setup import setup_logging
from lib.utils import read_lines, write_lines, run_command, deduplicate_domains, save_json


def _resolve_to_ips(hostnames: list[str], logger) -> dict[str, list[str]]:
    ip_to_hostnames: dict[str, list[str]] = {}
    for host in hostnames:
        result = run_command(["dig", "+short", host], timeout=10)
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                ip = line.strip()
                if ip and not ip.endswith(".") and "." in ip:
                    ip_to_hostnames.setdefault(ip, [])
                    if host not in ip_to_hostnames[ip]:
                        ip_to_hostnames[ip].append(host)
    return ip_to_hostnames


def _run_masscan(targets_file: str, output_file: str, config: dict, logger) -> list[str]:
    scan_config = config.get("port_scan", {})
    rate = scan_config.get("masscan_rate", 10000)
    top_ports = scan_config.get("masscan_top_ports", 100)

    if not shutil.which("masscan"):
        logger.warning("masscan not installed -- falling back to nmap ping scan")
        return _nmap_ping_scan(targets_file, logger)

    cmd = [
        "sudo", "masscan",
        "-iL", targets_file,
        f"--top-ports={top_ports}",
        f"--rate={rate}",
        "-oJ", output_file,
        "--open",
    ]

    logger.info(f"Running masscan (rate={rate}, top-ports={top_ports})...")
    result = run_command(cmd, timeout=600, logger=logger)

    if result.returncode != 0:
        logger.warning(f"masscan failed (exit {result.returncode}), falling back to nmap ping scan")
        return _nmap_ping_scan(targets_file, logger)

    alive_ips = set()
    try:
        with open(output_file) as f:
            content = f.read().strip()
            if content.endswith(","):
                content = content[:-1]
            if not content.startswith("["):
                content = "[" + content + "]"
            data = json.loads(content)
            for entry in data:
                ip = entry.get("ip", "")
                if ip:
                    alive_ips.add(ip)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.warning(f"Error parsing masscan output: {e}")
        return _nmap_ping_scan(targets_file, logger)

    logger.info(f"masscan found {len(alive_ips)} alive hosts")
    return sorted(alive_ips)


def _nmap_ping_scan(targets_file: str, logger) -> list[str]:
    logger.info("Running nmap ping scan for host discovery...")
    result = run_command(
        ["nmap", "-sn", "-iL", targets_file, "-oG", "-"],
        timeout=600,
        logger=logger,
    )

    alive_ips = []
    if result.returncode == 0:
        for line in result.stdout.split("\n"):
            if "Status: Up" in line:
                parts = line.split()
                if len(parts) >= 2:
                    alive_ips.append(parts[1])

    logger.info(f"nmap ping scan found {len(alive_ips)} alive hosts")
    return alive_ips


def _build_nmap_port_spec(config: dict) -> str:
    scan_config = config.get("port_scan", {})
    supplemental = scan_config.get("nmap_supplemental_ports", [])

    if supplemental:
        top_n = scan_config.get("nmap_top_ports", 1000)
        return f"--top-ports {top_n} -p {','.join(str(p) for p in supplemental)}"

    return f"--top-ports {scan_config.get('nmap_top_ports', 1000)}"


def _run_nmap(alive_file: str, output_dir: Path, config: dict, logger):
    scan_config = config.get("port_scan", {})
    options = scan_config.get("nmap_options", "-sV -sC --open")
    timing = scan_config.get("nmap_timing", "-T4")
    max_parallel = scan_config.get("nmap_max_parallelism", 20)
    supplemental = scan_config.get("nmap_supplemental_ports", [])
    top_ports = scan_config.get("nmap_top_ports", 1000)

    cmd = ["nmap", "-iL", alive_file]
    cmd.extend(options.split())
    cmd.extend(timing.split())

    if supplemental:
        port_list = ",".join(str(p) for p in supplemental)
        cmd.extend([f"--top-ports", str(top_ports), "-p", port_list])
    else:
        cmd.extend(["--top-ports", str(top_ports)])

    cmd.extend([f"--max-parallelism={max_parallel}"])
    cmd.extend(["-oX", str(output_dir / "nmap_results.xml")])
    cmd.extend(["-oG", str(output_dir / "nmap_results.gnmap")])
    cmd.extend(["-oN", str(output_dir / "nmap_results.nmap")])

    logger.info(f"Running nmap service scan...")
    logger.debug(f"nmap command: {' '.join(cmd)}")

    result = run_command(cmd, timeout=7200, logger=logger)

    if result.returncode != 0:
        logger.error("nmap scan failed")
        if result.stderr:
            logger.error(f"stderr: {result.stderr[:1000]}")
        return False

    logger.info("nmap scan completed")
    return True


def _nmap_xml_to_excel(xml_path: str, xlsx_path: str, ip_hostname_map: dict[str, list[str]], logger):
    from openpyxl import Workbook
    from openpyxl.styles import Font, Alignment
    from openpyxl.utils import get_column_letter

    tree = ET.parse(xml_path)
    root = tree.getroot()

    wb = Workbook()

    # Sheet 1: Hosts
    ws_hosts = wb.active
    ws_hosts.title = "Hosts"
    host_headers = ["IP Address", "Hostname", "OS Guess", "State", "Open Ports"]
    ws_hosts.append(host_headers)

    # Sheet 2: Services
    ws_services = wb.create_sheet("Services")
    svc_headers = ["IP Address", "Hostname", "Port", "Protocol", "State", "Service", "Version", "Extra Info"]
    ws_services.append(svc_headers)

    # Sheet 3: Summary
    ws_summary = wb.create_sheet("Summary")

    hosts_up = 0
    total_ports = 0

    for host in root.findall(".//host"):
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host.find("address")
        ip = addr_elem.get("addr", "N/A") if addr_elem is not None else "N/A"

        hostnames_from_map = ip_hostname_map.get(ip, [])
        hostname_elem = host.find(".//hostname")
        nmap_hostname = hostname_elem.get("name", "") if hostname_elem is not None else ""
        if nmap_hostname and nmap_hostname not in hostnames_from_map:
            hostnames_from_map.append(nmap_hostname)
        hostname = ", ".join(hostnames_from_map) if hostnames_from_map else nmap_hostname

        os_elem = host.find(".//osmatch")
        os_guess = os_elem.get("name", "") if os_elem is not None else ""

        status_elem = host.find("status")
        state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

        if state == "up":
            hosts_up += 1

        open_ports = []
        for port in host.findall(".//port"):
            port_state_elem = port.find("state")
            port_state = port_state_elem.get("state", "") if port_state_elem is not None else ""

            if "open" not in port_state:
                continue

            portid = port.get("portid", "")
            protocol = port.get("protocol", "")

            service_elem = port.find("service")
            service_name = ""
            product = ""
            version = ""
            extra = ""
            if service_elem is not None:
                service_name = service_elem.get("name", "")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")
                extra = service_elem.get("extrainfo", "")

            version_str = " ".join(filter(None, [product, version])).strip()

            ws_services.append([ip, hostname, portid, protocol, port_state, service_name, version_str, extra])
            open_ports.append(f"{portid}/{protocol}")
            total_ports += 1

        ws_hosts.append([ip, hostname, os_guess, state, len(open_ports)])

    # Summary sheet
    scan_info = root.find(".//runstats/finished")
    scan_time = scan_info.get("timestr", "N/A") if scan_info is not None else "N/A"
    elapsed = scan_info.get("elapsed", "N/A") if scan_info is not None else "N/A"

    summary_data = [
        ["Metric", "Value"],
        ["Total Hosts Scanned", len(root.findall(".//host"))],
        ["Hosts Up", hosts_up],
        ["Total Open Ports", total_ports],
        ["Scan Date", scan_time],
        ["Scan Duration (seconds)", elapsed],
    ]
    for row in summary_data:
        ws_summary.append(row)

    # Formatting
    bold = Font(bold=True)
    for ws in [ws_hosts, ws_services, ws_summary]:
        for cell in ws[1]:
            cell.font = bold
        ws.freeze_panes = "A2"

        for col_idx in range(1, ws.max_column + 1):
            max_len = 0
            for row in ws.iter_rows(min_col=col_idx, max_col=col_idx):
                for cell in row:
                    if cell.value:
                        max_len = max(max_len, len(str(cell.value)))
            ws.column_dimensions[get_column_letter(col_idx)].width = min(max_len + 2, 50)

    wb.save(xlsx_path)
    logger.info(f"Excel report saved: {xlsx_path}")
    logger.info(f"  Hosts: {hosts_up} up, Services: {total_ports} open ports")


def run(run_dir: Path, config: dict) -> bool:
    logger = setup_logging(run_dir, "s7_portscan")
    stage_dir = get_stage_dir(run_dir, "s7_portscan")

    xlsx_file = stage_dir / "port_scan_results.xlsx"
    if xlsx_file.exists():
        logger.info("Port scan already completed (Excel report exists)")
        return True

    # Gather targets: subdomains + IP ranges
    subdomains_file = run_dir / "s6_subdomains" / "subdomains.txt"
    ip_ranges_file = run_dir / "s2_asn" / "ip_ranges.txt"

    subdomains = read_lines(subdomains_file) if subdomains_file.exists() else []
    ip_ranges = read_lines(ip_ranges_file) if ip_ranges_file.exists() else []

    # Also include the final domain list
    domains_file = run_dir / "s5_cleanup" / "domains_final.txt"
    domains = read_lines(domains_file) if domains_file.exists() else []

    all_hostnames = deduplicate_domains(subdomains + domains)

    if not all_hostnames and not ip_ranges:
        logger.warning("No targets for port scanning")
        return True

    # Resolve hostnames to IPs (preserving all hostnames per IP)
    logger.info(f"Resolving {len(all_hostnames)} hostnames to IPs...")
    ip_to_hostnames = _resolve_to_ips(all_hostnames, logger)
    logger.info(f"Resolved to {len(ip_to_hostnames)} unique IPs")

    # Save the mapping for stage 8 (gowitness needs hostnames for proper HTTP Host headers)
    save_json(stage_dir / "ip_hostname_map.json", ip_to_hostnames)

    # Combine with IP ranges (expand CIDRs to individual IPs)
    from lib.utils import expand_cidr_to_ips
    range_ips = set()
    for cidr in ip_ranges:
        range_ips.update(expand_cidr_to_ips(cidr))

    all_ips = sorted(set(ip_to_hostnames.keys()) | range_ips)
    logger.info(f"Total unique target IPs: {len(all_ips)}")

    targets_file = stage_dir / "scan_targets.txt"
    write_lines(targets_file, all_ips)

    # Phase 1: Alive host discovery
    masscan_output = stage_dir / "masscan_output.json"
    alive_ips = _run_masscan(str(targets_file), str(masscan_output), config, logger)

    if not alive_ips:
        logger.warning("No alive hosts found")
        return True

    alive_file = stage_dir / "masscan_alive.txt"
    write_lines(alive_file, alive_ips)
    logger.info(f"Alive hosts: {len(alive_ips)}")

    # Phase 2: nmap service scan
    success = _run_nmap(str(alive_file), stage_dir, config, logger)
    if not success:
        return False

    # Phase 3: Convert to Excel
    xml_path = stage_dir / "nmap_results.xml"
    if xml_path.exists():
        _nmap_xml_to_excel(str(xml_path), str(xlsx_file), ip_to_hostnames, logger)
    else:
        logger.error("nmap XML output not found")
        return False

    return True


def main():
    parser = argparse.ArgumentParser(description="Stage 7: Port Scanning")
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
