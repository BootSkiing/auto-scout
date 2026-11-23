#!/usr/bin/env python3
"""
Stage 7: Port Scanning
masscan for alive host discovery, nmap for service fingerprinting,
XML-to-Excel conversion.
"""
import argparse
import concurrent.futures
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
from lib.utils import (
    read_lines,
    write_lines,
    run_command,
    deduplicate_domains,
    save_json,
    has_underscore_label,
    clean_stage_dir,
)


def _resolve_one(host: str) -> tuple[str, list[str]]:
    """Resolve a single hostname to its IPv4 address(es). Returns (host, ips).

    dig is bounded with +time=2 +tries=1 so one unresponsive resolver can't
    stall for ~15s (its default 5s x 3 tries); the 5s subprocess timeout is a
    backstop, and run_command turns any timeout into an empty result rather
    than an exception.
    """
    result = run_command(
        ["dig", "+short", "+time=2", "+tries=1", "A", host],
        timeout=5,
    )
    ips: list[str] = []
    if result.returncode == 0:
        for line in result.stdout.strip().split("\n"):
            ip = line.strip()
            if ip and not ip.endswith(".") and "." in ip:
                ips.append(ip)
    return host, ips


def _resolve_to_ips(
    hostnames: list[str], logger, max_workers: int = 100
) -> tuple[dict[str, list[str]], list[str]]:
    """Resolve hostnames to IPv4 addresses concurrently.

    Returns (ip_to_hostnames, unresolved): the map preserves every hostname
    that resolved, grouped by IP; unresolved lists names that returned no
    usable A record (NXDOMAIN, CNAME-only chains with no address, etc.).

    Resolution is parallelized across a thread pool -- each lookup is an
    I/O-blocked dig subprocess, so threads scale well and 18k names drop from
    hours (serial) to minutes. Input is already deduplicated upstream, so
    hostnames are appended without a per-IP membership scan (which would go
    quadratic when a wildcard record maps thousands of names to one IP).
    """
    ip_to_hostnames: dict[str, list[str]] = {}
    unresolved: list[str] = []
    workers = max(1, min(max_workers, len(hostnames))) if hostnames else 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for host, ips in pool.map(_resolve_one, hostnames):
            if ips:
                for ip in ips:
                    ip_to_hostnames.setdefault(ip, []).append(host)
            else:
                unresolved.append(host)
    return ip_to_hostnames, unresolved


def _resolution_gate(all_hostnames: list[str], stage_dir: Path, logger) -> dict[str, list[str]]:
    """Phase 0 of stage 7: turn a candidate hostname list into scan targets.

    Two passes, each recorded rather than silently dropped:
      1. Filter out underscore/service labels (_dmarc, _acme-challenge,
         _sip._tcp, and the _wildcard CT-log artifact) -- none are hosts.
      2. Resolve the remainder to IPv4; names with no A record are set aside.

    Returns ip_to_hostnames for the names that resolved. The full audit (what
    was filtered, what failed to resolve) is written to resolution_gate.json.
    """
    scannable: list[str] = []
    service_labels: list[str] = []
    for host in all_hostnames:
        (service_labels if has_underscore_label(host) else scannable).append(host)

    if service_labels:
        logger.info(
            f"Resolution gate: filtered {len(service_labels)} underscore/service "
            f"labels (e.g. _dmarc, _acme-challenge, _wildcard) -- not hosts"
        )

    logger.info(f"Resolution gate: resolving {len(scannable)} candidate hostnames...")
    ip_to_hostnames, unresolved = _resolve_to_ips(scannable, logger)
    logger.info(
        f"Resolution gate: {len(ip_to_hostnames)} unique IPs resolved; "
        f"{len(unresolved)} names did not resolve"
    )

    save_json(stage_dir / "resolution_gate.json", {
        "input_hostnames": len(all_hostnames),
        "filtered_service_labels": sorted(service_labels),
        "resolved_ip_count": len(ip_to_hostnames),
        "unresolved_hostnames": sorted(unresolved),
    })
    return ip_to_hostnames


def _run_masscan(targets_file: str, output_file: str, config: dict, logger) -> list[str]:
    scan_config = config.get("port_scan", {})
    rate = scan_config.get("masscan_rate", 10000)
    top_ports = scan_config.get("masscan_top_ports", 100)
    # Host-discovery timeout. masscan runtime scales as (#targets x #ports)/rate,
    # so at 18k+ targets the old fixed 600s was marginal; make it configurable.
    discovery_timeout = scan_config.get("masscan_timeout", 1800)

    if not shutil.which("masscan"):
        logger.warning("masscan not installed -- falling back to nmap ping scan")
        return _nmap_ping_scan(targets_file, logger, discovery_timeout)

    cmd = [
        "sudo", "-n", "masscan",
        "-iL", targets_file,
        f"--top-ports={top_ports}",
        f"--rate={rate}",
        "-oJ", output_file,
        "--open",
    ]

    logger.info(f"Running masscan (rate={rate}, top-ports={top_ports})...")
    result = run_command(cmd, timeout=discovery_timeout, logger=logger)

    if result.returncode != 0:
        logger.warning(
            f"masscan failed (exit {result.returncode}), falling back to nmap ping scan. "
            f"If this is a sudo error, configure passwordless sudo for masscan "
            f"(sudo -n is used so the scan never blocks on a password prompt)."
        )
        if result.stderr:
            logger.warning(f"masscan stderr: {result.stderr[:500]}")
        return _nmap_ping_scan(targets_file, logger, discovery_timeout)

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


def _nmap_ping_scan(targets_file: str, logger, timeout: int = 1800) -> list[str]:
    logger.info("Running nmap ping scan for host discovery...")
    result = run_command(
        ["nmap", "-sn", "-iL", targets_file, "-oG", "-"],
        timeout=timeout,
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


def _merge_nmap_xml(xml_paths: list[Path], logger) -> "ET.ElementTree | None":
    """Merge per-batch nmap XML into one tree for the Excel step.

    The first parseable batch supplies the <nmaprun> root; <host> elements from
    every other batch are appended onto it and the runstats elapsed time is
    summed. Batches that can't be parsed (e.g. one killed on timeout before it
    flushed valid XML) are skipped with a warning. Returns None if nothing
    parsed.
    """
    base_tree = None
    base_root = None
    total_elapsed = 0.0

    for path in xml_paths:
        try:
            tree = ET.parse(str(path))
        except (ET.ParseError, FileNotFoundError) as e:
            logger.warning(f"Skipping unparseable nmap XML {path.name}: {e}")
            continue
        root = tree.getroot()
        if base_root is None:
            base_tree, base_root = tree, root
        else:
            for host in root.findall("host"):
                base_root.append(host)
        finished = root.find("runstats/finished")
        if finished is not None:
            try:
                total_elapsed += float(finished.get("elapsed", "0") or 0)
            except ValueError:
                pass

    if base_root is None:
        return None

    finished = base_root.find("runstats/finished")
    if finished is not None:
        finished.set("elapsed", f"{total_elapsed:.2f}")
    return base_tree


def _run_nmap(targets_file: str, output_dir: Path, config: dict, logger):
    scan_config = config.get("port_scan", {})
    options = scan_config.get("nmap_options", "-sV --open")
    timing = scan_config.get("nmap_timing", "-T4")
    max_parallel = scan_config.get("nmap_max_parallelism", 20)
    supplemental = scan_config.get("nmap_supplemental_ports", [])
    top_ports = scan_config.get("nmap_top_ports", 1000)
    batch_size = scan_config.get("nmap_batch_size", 1000)
    batch_timeout = scan_config.get("nmap_timeout", 3600)

    targets = read_lines(targets_file)
    if not targets:
        logger.warning("No nmap targets to scan")
        return False

    # Argument tail shared by every batch (all but -iL and the -o* outputs).
    base_args: list[str] = []
    base_args.extend(options.split())
    base_args.extend(timing.split())
    if supplemental:
        port_list = ",".join(str(p) for p in supplemental)
        base_args.extend(["--top-ports", str(top_ports), "-p", port_list])
    else:
        base_args.extend(["--top-ports", str(top_ports)])
    base_args.append(f"--max-parallelism={max_parallel}")

    # Shard the host list so one slow/stuck batch (hitting the per-batch
    # timeout) can't take down the whole scan -- failed batches are logged and
    # skipped, and the batches that finished are still reported.
    batches = [targets[i:i + batch_size] for i in range(0, len(targets), batch_size)]
    logger.info(
        f"Running nmap service scan: {len(targets)} targets in {len(batches)} "
        f"batch(es) of up to {batch_size} (per-batch timeout {batch_timeout}s)"
    )

    batch_xmls: list[Path] = []
    for idx, batch in enumerate(batches, 1):
        batch_file = output_dir / f"nmap_batch_{idx}.txt"
        write_lines(batch_file, batch)
        xml_out = output_dir / f"nmap_results_{idx}.xml"

        cmd = ["nmap", "-iL", str(batch_file)] + base_args
        cmd.extend(["-oX", str(xml_out)])
        cmd.extend(["-oN", str(output_dir / f"nmap_results_{idx}.nmap")])
        cmd.extend(["-oG", str(output_dir / f"nmap_results_{idx}.gnmap")])

        logger.info(f"nmap batch {idx}/{len(batches)} ({len(batch)} targets)...")
        logger.debug(f"nmap command: {' '.join(cmd)}")
        result = run_command(cmd, timeout=batch_timeout, logger=logger)

        if result.returncode != 0:
            logger.warning(
                f"nmap batch {idx}/{len(batches)} did not finish cleanly "
                f"(exit {result.returncode}); continuing with remaining batches"
            )
        if xml_out.exists():
            batch_xmls.append(xml_out)

    merged = _merge_nmap_xml(batch_xmls, logger)
    if merged is None:
        logger.error("nmap produced no parseable output for any batch")
        return False

    merged.write(str(output_dir / "nmap_results.xml"))
    logger.info(
        f"nmap scan completed ({len(batch_xmls)}/{len(batches)} batches produced output)"
    )
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

    # Port scanning has no human-review gate; whenever this stage is invoked it
    # re-scans. Clear regenerated artifacts first so stale batch/scan files from
    # a previous (possibly larger) run can't be merged into the new report.
    clean_stage_dir(stage_dir, logger=logger)

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

    # Phase 0: resolution gate -- filter non-host labels, resolve the rest,
    # and record what was dropped. Preserves every resolved hostname per IP.
    ip_to_hostnames = _resolution_gate(all_hostnames, stage_dir, logger)

    # Save the mapping for stage 8 (gowitness needs hostnames for proper HTTP Host headers)
    save_json(stage_dir / "ip_hostname_map.json", ip_to_hostnames)

    # Combine resolved IPs with the IP ranges. masscan accepts both individual
    # IPs and CIDR notation in its target file, so ranges are passed as-is
    # rather than expanded to individual hosts -- a single /16 would otherwise
    # become 65k lines (and larger ranges, millions), blowing up memory and the
    # target file for no benefit. masscan deduplicates overlaps itself.
    resolved_ips = sorted(ip_to_hostnames.keys())
    cidr_ranges = sorted(set(ip_ranges))
    scan_targets = resolved_ips + cidr_ranges
    logger.info(
        f"Scan targets: {len(resolved_ips)} resolved IPs + "
        f"{len(cidr_ranges)} CIDR ranges"
    )

    targets_file = stage_dir / "scan_targets.txt"
    write_lines(targets_file, scan_targets)

    # Phase 1: Alive host discovery
    masscan_output = stage_dir / "masscan_output.json"
    alive_ips = _run_masscan(str(targets_file), str(masscan_output), config, logger)

    if not alive_ips:
        logger.warning("No alive hosts found")
        return True

    alive_file = stage_dir / "masscan_alive.txt"
    write_lines(alive_file, alive_ips)
    logger.info(f"Alive hosts: {len(alive_ips)}")

    # Build nmap targets: one representative hostname per alive IP so nmap
    # performs its own DNS lookup and records the name natively in its XML;
    # fall back to the bare IP when an alive IP has no associated hostname
    # (e.g. one discovered only via a CIDR range). The complete hostname list
    # per IP is still carried in ip_hostname_map and merged into the report,
    # so scanning one name per IP loses no association.
    nmap_targets: list[str] = []
    named = 0
    for ip in alive_ips:
        names = sorted(ip_to_hostnames.get(ip, []))
        if names:
            nmap_targets.append(names[0])
            named += 1
        else:
            nmap_targets.append(ip)

    nmap_targets_file = stage_dir / "nmap_targets.txt"
    write_lines(nmap_targets_file, nmap_targets)
    logger.info(
        f"nmap targets: {named} by hostname, {len(nmap_targets) - named} by IP"
    )

    # Phase 2: nmap service scan
    success = _run_nmap(str(nmap_targets_file), stage_dir, config, logger)
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
