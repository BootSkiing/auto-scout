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


def _masscan_port_args(config: dict) -> tuple[list[str], str]:
    """masscan's port-selection args + a short label, per scan_mode.

    full      -> every TCP port (-p1-65535): nothing on a high port is missed.
    top-ports -> the top N ports only (fast).
    """
    scan_config = config.get("port_scan", {})
    if scan_config.get("scan_mode", "full") == "top-ports":
        top = scan_config.get("masscan_top_ports", 1000)
        return [f"--top-ports={top}"], f"top-{top}"
    return ["-p", "1-65535"], "all-65535"


def _parse_masscan(output_file: str, logger) -> dict[str, list[int]]:
    """Parse masscan -oJ into {ip: [open tcp ports]} (sorted). {} on any error."""
    ip_ports: dict[str, set[int]] = {}
    try:
        with open(output_file) as f:
            content = f.read().strip()
    except FileNotFoundError:
        return {}
    # Normalise masscan -oJ, tolerating a file an interrupted scan left without
    # its closing bracket (and the trailing "," between records).
    content = content.rstrip().rstrip(",").rstrip()
    if not content:
        return {}
    if not content.startswith("["):
        content = "[" + content
    if not content.endswith("]"):
        content = content + "]"
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.warning(f"Error parsing masscan output: {e}")
        return {}
    for entry in data:
        ip = entry.get("ip", "")
        if not ip:
            continue
        for p in entry.get("ports", []):
            if p.get("status") == "open" and p.get("proto") == "tcp":
                try:
                    ip_ports.setdefault(ip, set()).add(int(p["port"]))
                except (KeyError, ValueError):
                    continue
    return {ip: sorted(ports) for ip, ports in ip_ports.items()}


def _run_masscan(targets_file: str, output_file: str, config: dict, logger) -> "dict[str, list[int]] | None":
    """Run masscan; return {ip: [open ports]}.

    masscan's own open-port results ARE the host discovery -- a host appears iff
    it has an open port, so there is no separate liveness step to miss a
    high-port-only host. Returns {} when the scan ran but found nothing, and
    None only when masscan is unavailable or failed with no salvageable output
    (so the caller can fall back to a direct nmap scan). Partial output from an
    interrupted multi-day scan is kept rather than discarded.
    """
    scan_config = config.get("port_scan", {})
    rate = scan_config.get("masscan_rate", 40000)
    retries = scan_config.get("masscan_retries", 1)
    mode = scan_config.get("scan_mode", "full")
    # Optional fixed source port. When set, pair it with a firewall rule that
    # drops inbound traffic to this port so the kernel never sees masscan's
    # SYN-ACKs and never answers them with a RST (masscan captures them via pcap
    # regardless). Leave unset to let masscan pick its own port.
    source_port = scan_config.get("masscan_source_port")
    # A full scan runs for days -- default to no timeout there; top-ports keeps a
    # bound. masscan_timeout in config overrides either (null = no timeout).
    default_timeout = None if mode == "full" else 1800
    timeout = scan_config.get("masscan_timeout", default_timeout)

    if not shutil.which("masscan"):
        logger.warning("masscan not installed -- cannot run the port sweep")
        return None

    port_args, label = _masscan_port_args(config)
    cmd = [
        "sudo", "-n", "masscan",
        "-iL", targets_file,
        *port_args,
        f"--rate={rate}",
        f"--retries={retries}",
        "-oJ", output_file,
        "--open",
    ]
    if source_port:
        cmd.append(f"--source-port={source_port}")

    logger.info(
        f"Running masscan (mode={mode}/{label}, rate={rate}, retries={retries}, "
        f"source-port={source_port or 'auto'}, "
        f"timeout={'none' if timeout is None else str(timeout) + 's'})..."
    )
    result = run_command(cmd, timeout=timeout, logger=logger)

    if result.returncode != 0:
        logger.warning(
            f"masscan exited non-zero ({result.returncode}). If this is a sudo "
            f"error, configure passwordless sudo for masscan (sudo -n is used so "
            f"the scan never blocks on a password prompt)."
        )
        if result.stderr:
            logger.warning(f"masscan stderr: {result.stderr[:500]}")

    ip_ports = _parse_masscan(output_file, logger)

    if not ip_ports:
        # Nothing parsed: treat a clean exit as "legitimately empty", a non-zero
        # exit as a real failure the caller should fall back from.
        return None if result.returncode != 0 else {}

    if result.returncode != 0:
        logger.warning(
            f"Using partial masscan results ({len(ip_ports)} hosts) despite the "
            f"non-zero exit."
        )

    total_ports = sum(len(v) for v in ip_ports.values())
    logger.info(
        f"masscan found {len(ip_ports)} hosts with open ports ({total_ports} open ports total)"
    )
    return ip_ports


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


def _run_nmap_jobs(
    jobs: list[tuple[list[str], list[str]]],
    output_dir: Path,
    config: dict,
    logger,
    known_up: bool,
):
    """Run nmap for a set of (targets, port_args) jobs and merge the XML.

    Each job scans its targets on its own ports, so a host is service-probed
    only on the ports masscan actually found open -- no re-discovery. known_up
    adds -Pn (skip host discovery) because masscan already proved the hosts
    have open ports; skipping it avoids dropping a host that ignores pings.
    Large jobs are sharded by nmap_batch_size so one stuck batch can't take the
    whole scan down (failed batches are logged, skipped, and the rest reported).
    """
    scan_config = config.get("port_scan", {})
    options = scan_config.get("nmap_options", "-sV --open --version-intensity 7")
    timing = scan_config.get("nmap_timing", "-T4")
    max_parallel = scan_config.get("nmap_max_parallelism", 50)
    batch_size = scan_config.get("nmap_batch_size", 1000)
    batch_timeout = scan_config.get("nmap_timeout", 3600)

    base_args = options.split() + timing.split()
    if known_up:
        base_args.append("-Pn")
    base_args.append(f"--max-parallelism={max_parallel}")

    # Flatten jobs into batches, sharding any job whose target list is large.
    batches: list[tuple[list[str], list[str]]] = []
    for targets, port_args in jobs:
        for i in range(0, len(targets), batch_size):
            batches.append((targets[i:i + batch_size], port_args))

    if not batches:
        logger.warning("No nmap targets to scan")
        return False

    total_targets = sum(len(t) for t, _ in jobs)
    logger.info(
        f"Running nmap service scan: {total_targets} host(s) in {len(batches)} "
        f"batch(es) (per-batch timeout {batch_timeout}s)"
    )

    batch_xmls: list[Path] = []
    for idx, (targets, port_args) in enumerate(batches, 1):
        batch_file = output_dir / f"nmap_batch_{idx}.txt"
        write_lines(batch_file, targets)
        xml_out = output_dir / f"nmap_results_{idx}.xml"

        cmd = ["nmap", "-iL", str(batch_file)] + base_args + port_args
        cmd += ["-oX", str(xml_out),
                "-oN", str(output_dir / f"nmap_results_{idx}.nmap"),
                "-oG", str(output_dir / f"nmap_results_{idx}.gnmap")]

        logger.info(f"nmap batch {idx}/{len(batches)} ({len(targets)} host(s))...")
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

    # Phase 1: masscan port sweep. Its open-ports-per-host IS the discovery --
    # any host with an open port is found, so there is no separate liveness step
    # that could miss a high-port-only host.
    masscan_output = stage_dir / "masscan_output.json"
    ip_ports = _run_masscan(str(targets_file), str(masscan_output), config, logger)

    scan_cfg = config.get("port_scan", {})
    cap = int(scan_cfg.get("max_open_ports_per_host", 500))

    if ip_ports is not None:
        if not ip_ports:
            logger.warning("No hosts with open ports found")
            return True

        # Hosts reporting an implausible number of open ports are almost always a
        # firewall/LB/tarpit faking open; feeding thousands of ports to nmap -sV
        # would hang. Record and skip them for the service scan.
        filtered = {ip: p for ip, p in ip_ports.items() if len(p) > cap}
        scannable = {ip: p for ip, p in ip_ports.items() if len(p) <= cap}
        if filtered:
            save_json(stage_dir / "filtered_hosts.json",
                      {ip: len(p) for ip, p in sorted(filtered.items())})
            logger.warning(
                f"{len(filtered)} host(s) exceeded max_open_ports_per_host={cap} "
                f"(likely filtered/all-open); skipped for service scan -- see "
                f"filtered_hosts.json"
            )

        save_json(stage_dir / "masscan_open_ports.json",
                  dict(sorted(ip_ports.items())))
        write_lines(stage_dir / "masscan_alive.txt", sorted(scannable.keys()))

        # Group hosts by their exact open-port set, so each distinct set is one
        # nmap job (the common {80,443} collapses to a single invocation) while
        # each host is still probed only on the ports it actually has open. The
        # representative hostname per IP lets nmap record the name natively; the
        # full hostname list per IP stays in ip_hostname_map for the report.
        groups: dict[tuple[int, ...], list[str]] = {}
        named = 0
        for ip, ports in scannable.items():
            names = sorted(ip_to_hostnames.get(ip, []))
            if names:
                named += 1
            groups.setdefault(tuple(ports), []).append(names[0] if names else ip)

        jobs = [
            (targets, ["-p", ",".join(str(p) for p in ports)])
            for ports, targets in groups.items()
        ]
        logger.info(
            f"Service-scanning {len(scannable)} host(s) in {len(jobs)} distinct "
            f"port-set group(s); {named} scanned by hostname"
        )
        success = _run_nmap_jobs(jobs, stage_dir, config, logger, known_up=True)
    else:
        # Fallback: no masscan -> nmap does discovery + service itself. Much
        # slower (full mode scans every port), host discovery left on to avoid
        # fully scanning dead space. masscan is strongly recommended here.
        mode = scan_cfg.get("scan_mode", "full")
        port_args = (["--top-ports", str(scan_cfg.get("nmap_top_ports", 1000))]
                     if mode == "top-ports" else ["-p-"])
        logger.warning(
            f"Falling back to a direct nmap scan without masscan (mode={mode}); "
            f"this is slow. Install masscan / fix passwordless sudo for speed."
        )
        fb_targets = [sorted(ip_to_hostnames.get(ip, [ip]))[0] for ip in resolved_ips]
        fb_targets += cidr_ranges
        success = _run_nmap_jobs([(fb_targets, port_args)], stage_dir, config, logger,
                                 known_up=False)

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
