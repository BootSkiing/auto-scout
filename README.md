# Auto-Scout

```text
            0000       0          0       0000
            017800000000          000030005 10
           01         00          00         70
          0        30 000        000 0        50
         01        0 01 0006669707700 0        80
        0          0 0 70        07 0 0         05
       00    00       070   00   0301      00    50
        0000         0250        00 0         0500
      000 09000006 00000 96   20  00000600000000 000
                000      07     0      000
                000       000000       000
                  0        0000        02

                   A U T O - S C O U T
```

Automated external asset enumeration. Given a few hand-selected seeds, Auto-Scout will perform staged recon to identify internet-facing assets. Stages can run independently of each other or be strung together for an all-in-one solution to external footprinting. Explicit review gates allow for out-of-scope artifacts to be identified and removed mid-run. Auto-Scout has the ability to perform:

- ASN Lookups
- Reverse DNS Resolution
- Reverse WHOIS Lookups
- Subdomain Enumeration (w/ [BBOT](https://github.com/blacklanternsecurity/bbot))
- Port Scanning and Service Discovery (w/ [masscan](https://github.com/robertdavidgraham/massca) and [nmap](https://github.com/nmap/nmap))
- Web Screenshotting (w/ [gowitness](https://github.com/sensepost/gowitness))
- Email and Google Dorking Checks

By now you should have realized this is a slopped together monolithic python script that strings together a bunch of other people's tools and ideas. All I can say is: it fits my workflow. I needed a way to identify all external assets for a huge organization spanning many subsidiaries. I wanted something that would give me both speed and accuracy, and I didn't really want to deal with someone else's preferences. The result is something that I can easily deploy on an EC2, forget about for a week, and come back to a beefy excel sheet with all the data I need and minimal garbage.

## Options

```
 ______     __  __     ______   ______     ______     ______     ______     __  __     ______
/\  __ \   /\ \/\ \   /\__  _\ /\  __ \   /\  ___\   /\  ___\   /\  __ \   /\ \/\ \   /\__  _\
\ \  __ \  \ \ \_\ \  \/_/\ \/ \ \ \/\ \  \ \___  \  \ \ \____  \ \ \/\ \  \ \ \_\ \  \/_/\ \/
 \ \_\ \_\  \ \_____\    \ \_\  \ \_____\  \/\_____\  \ \_____\  \ \_____\  \ \_____\    \ \_\
  \/_/\/_/   \/_____/     \/_/   \/_____/   \/_____/   \/_____/   \/_____/   \/_____/     \/_/

                          :: external asset enumeration pipeline ::

usage: run.sh [-h] [--config CONFIG] [--date DATE] [--from-stage {s1_seeds,s2_asn,s3_rdns,s4_rwhois,s5_cleanup,s6_subdomains,s7_portscan,s8_web,s9_extras}]
                       [--only {s1_seeds,s2_asn,s3_rdns,s4_rwhois,s5_cleanup,s6_subdomains,s7_portscan,s8_web,s9_extras}] [--through {s1_seeds,s2_asn,s3_rdns,s4_rwhois,s5_cleanup,s6_subdomains,s7_portscan,s8_web,s9_extras}]
                       [--review-mode {halt,auto}] [--force] [--rdns-mode {api,bulk}]

Auto-Scout - External Asset Enumeration Pipeline

options:
  -h, --help            show this help message and exit
  --config CONFIG       Path to config file
  --date DATE           Run date override (YYYY-MM-DD)
  --from-stage {s1_seeds,s2_asn,s3_rdns,s4_rwhois,s5_cleanup,s6_subdomains,s7_portscan,s8_web,s9_extras}
                        Resume from this stage
  --only {s1_seeds,s2_asn,s3_rdns,s4_rwhois,s5_cleanup,s6_subdomains,s7_portscan,s8_web,s9_extras}
                        Run only this stage
  --through {s1_seeds,s2_asn,s3_rdns,s4_rwhois,s5_cleanup,s6_subdomains,s7_portscan,s8_web,s9_extras}
                        Run stages up through this one
  --review-mode {halt,auto}
                        Override review gate behavior
  --force               Re-run even completed stages, wiping each stage's dir first (approved files and resume progress included) for a clean-slate run
  --rdns-mode {api,bulk}
                        s3 reverse-DNS backend: 'api' (per-IP THC API, default) or 'bulk' (local DuckDB query over THC's bulk parquet; requires reverse_dns.bulk.parquet_path)
```

### Usage

```bash
./run.sh                               # full run; halts at each review gate (stages 2, 3, 4)
./run.sh --date 2026-10-29             # resume a run: skips completed stages, picks up approved reviews
./run.sh --from-stage s6_subdomains    # resume from a given stage
./run.sh --only s7_portscan            # run a single stage
./run.sh --through s5_cleanup          # run stages 1 through N
./run.sh --review-mode auto            # unattended: auto-approve all review gates
./run.sh --rdns-mode bulk              # stage 3 via offline snapshot instead of the live API
./run.sh --force                       # re-run even completed stages from a clean slate
```

## Setup

```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv pipx nmap masscan chromium-browser
git clone https://github.com/BootSkiing/auto-scout && cd auto-scout
python3 -m venv . && source bin/activate
./setup.sh                             # installs deps, bbot (pipx), gowitness; creates seed templates
cp config.example.yaml config.yaml     # then add your API keys
```

### Configuration

Everything lives in `config.yaml`. The essentials:

- **API keys** — `api_keys.whoxy` is the only key the core pipeline requires ([whoxy.com](https://www.whoxy.com/), buy reverse WHOIS credits). Shodan / Censys / SecurityTrails / VirusTotal / GitHub / Chaos keys are optional and improve stage-6 subdomain coverage.
- **Review mode** — `review.mode: halt` (default; stop for manual review) or `auto` (unattended, auto-approve).
- **Port scanning** — `port_scan.scan_mode: full` (all 65,535 ports) or `top-ports` (fast); rate, retries, timeouts, and the all-open cap are tunable. See [Stage 7](#stage-7-port-scanning-s7_portscan) and [Gotchas](#gotchas).
- **Excluded Domain Patterns** - `cleanup.excluded_domain_patterns` defines common CDN, WAF, and other domains that will slow down and/or pollute your scan - these get removed automatically during stages 3, 4, and 5. These are separate from Out-of-Scope domains (defined in `seeds/out_of_scope_{domains,terms,asns}.txt`).

**Review workflow:** in halt mode the run stops at stages 2 - 4 and prints a `*_review.*` file. Edit it, save it as the matching `*_approved.*` file (e.g. `asns_review.json` > `asns_approved.json`), and re-run the script with the same `--date`. Completed stages are skipped; a waiting stage picks up from the approved file.
For better visibility, every scope removal is logged to `<stage>/scope_removed.json`.

### Seed files

Manual inputs in `seeds/` (one entry per line, `#` for comments); `setup.sh` creates templates.

| File | Purpose | Required |
|---|---|---|
| `corporations.txt` | names to search for ASNs | **yes** |
| `domains.txt` | known root domains | **yes** |
| `whois_{names,orgs,emails}.txt` | reverse-WHOIS search terms | no |
| `out_of_scope_{domains,terms,asns}.txt` | scope exclusions (see above) | no |

Build corporation/WHOIS seeds from Crunchbase, SEC filings, OpenCorporates, Wikipedia, and the WHOIS records of core domains associated with those corporations.

## Stages

### Stage 1: Seeds (`s1_seeds`)
Validates that required seed files exist and are non-empty, and snapshots them into `runs/<date>/seeds/` so each run is self-documenting.

### Stage 2: ASN Discovery (`s2_asn`)
Downloads the [asndb.network](https://asndb.network) datasets, matches `corporations.txt` names (case-insensitive substring), and extracts the CIDR prefixes for matched ASNs.
**Review gate:** `asns_review.json` lists each matched ASN (`"include": true`); set `false` to drop one, save as `asns_approved.json`. **Output:** `ip_ranges.txt`.

### Stage 3: Reverse DNS (`s3_rdns`)
Finds domains hosted on the stage-2 IP ranges via [ip.thc.org](https://ip.thc.org). Two modes are avaialable via (`--rdns-mode`): `api` (default, uses the rate-limited web API) or `bulk` (analyzes an offline archive file — see [Bulk reverse DNS](#bulk-reverse-dns-optional)).
**Review gate:** `domains_review.txt`, pre-filtered against the exclusion patterns and out-of-scope domains → save as `domains_approved.txt`.

### Stage 4: Reverse WHOIS (`s4_rwhois`)
Queries Whoxy by registrant name, organization, and email (`whois_{names,orgs,emails}.txt` seeds).
**Review gate:** same as stage 3 — `domains_review.txt` → `domains_approved.txt`.

### Stage 5: Cleanup (`s5_cleanup`)
Merges domains from seeds + stages 3/4, deduplicates, applies the exclusion patterns and out-of-scope domains, and runs threaded parking-page detection (domains that time out are kept — they may be internal/VPN-only). This is where seed domains get scope-checked and the backstop for anything approved before it was marked out of scope.
**Output:** `domains_final.txt`, the master list for all later stages.

### Stage 6: Subdomain Enumeration (`s6_subdomains`)
Runs BBOT subdomain enumeration against every domain in `domains_final.txt`, in batches to manage memory, using the configured API keys for coverage. New subdomains are filtered against out-of-scope domains before being written (no human gate here). The BBOT scan uses passive and active techniques for discovery; some modules have been disabled by default to improve tool performance.
**Output:** `subdomains.txt`, `subdomains_by_domain.json`.

### Stage 7: Port Scanning (`s7_portscan`)
1. **Resolution gate** — drops non-host labels (underscore/service records like `_dmarc`, `_acme-challenge`, and `_wildcard` cert-transparency artifact), resolves the remaining names to IPs (parallel `dig`), and folds in the stage-2 CIDR ranges. Filtered/unresolved names are logged to `resolution_gate.json`.
2. **masscan** — sweeps ports across all target IPs (all 65,535 in `full` mode; top-N in `top-ports`). Its open-ports-per-host results *are* the discovery, so a host whose only open port is uncommon isn't missed, and partial output from an interrupted scan is salvaged.
3. **nmap** — service/version scan run per-host on the ports masscan found open, grouped by port-set and sharded into batches. Hosts reporting more than `max_open_ports_per_host` open (likely firewall/LB/tarpit) are logged to `filtered_hosts.json` and skipped. Each IP is scanned via one representative hostname so nmap records the name natively; the full name-per-IP map is kept in `ip_hostname_map.json`.
4. Merges the per-batch nmap XML output into an Excel workbook (Hosts / Services / Summary).

Re-running always re-scans (no "already done" short-circuit) and clears stale artifacts first. If masscan is unavailable, nmap does discovery itself (slower).
**Output:** `port_scan_results.xlsx` + the JSON/text artifacts above.

### Stage 8: Web Analysis (`s8_web`)
Screenshots every HTTP service nmap identified (by service/product, any port) with gowitness; a fallback port list covers open ports nmap couldn't fingerprint.
**Output:** `gowitness.sqlite3`, `screenshots/`. Browse with:
```bash
gowitness report server --db-uri sqlite:///path/to/runs/<date>/s8_web/gowitness.sqlite3 --screenshot-path /path/to/runs/<date>/s8_web/screenshots
```

### Stage 9: Extras (`s9_extras`)
- **DNS Email security** — SPF/DMARC/DKIM per domain; flags missing records, permissive SPF (`+all`/`~all`), unenforced DMARC (`p=none`). → `dns_security.json`.
- **Google dorks** — generated per domain/corporation (exposed files, admin panels, listings, backups). → `dorks.txt`.

## Bulk reverse DNS (optional)

Stage 3's default API is rate-limited. For querying big ranges, it makes more sense to download and query THC's monthly snapshot offline with DuckDB instead. See [https://ip.thc.org/docs/bulk-data-access](https://ip.thc.org/docs/bulk-data-access).

```bash
curl https://install.duckdb.org | sh
curl -L -C - -o rdns.parquet.gz '<huggingface-link>'
gunzip rdns.parquet.gz
# 4. set reverse_dns.bulk.parquet_path in config.yaml, then:
./run.sh --rdns-mode bulk
```

- **Disk:** budget ~130GB free during decompression (snapshot ~51GB, uncompressed ~79GB)
- `ip`/`domain` columns auto-detect from the schema; override via `reverse_dns.bulk.{ip,domain}_column` if detection fails.

## Gotchas

- **No proxychains / SOCKS / HTTP proxies** masscan, nmap SYN scans, and `dig` use raw sockets/UDP that bypass application-layer proxies — your traffic leaks around them silently. To scan from a non-residential IP: run on a cloud VPS directly, or route everything through a WireGuard tunnel (network-layer, so it catches raw sockets).
- **masscan needs passwordless sudo** It's run as `sudo -n masscan`, again because of raw sockets. You'll need to adjust the sudo permissions on this binary for a fully hands-off run.
- **Disable Linux Kernel RST Packets** Consider configuring the `masscan_source_port` parameter and adding an iptables RST-drop rule so the kernel doesn't automatically reset masscan's probes.
- **Scanning from EC2** Keep an eye on cloud resources, specifically **ENA packets-per-second allowance** and **security-group connection tracking** — start `masscan_rate` conservatively and watch the ENA CloudWatch `*_allowance_exceeded` counters. Make scan flows *untracked* (an all-traffic `0.0.0.0/0` Security Group rule in both directions) to dodge conntrack drops
