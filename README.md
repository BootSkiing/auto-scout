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

> An AI-controlled scout for your external attack surface — named after the
> Auto-Scout drone from [FTL: Faster Than Light](https://subsetgames.com/ftl.html).

An automated external asset enumeration pipeline for authorized security assessments. The pipeline discovers internet-facing assets through ASN lookups, reverse DNS, reverse WHOIS, and subdomain enumeration, and performs follow-up recon via port scanning and web screenshotting.

Each stage reads input files, produces output files, and can be run independently. Human review gates pause the pipeline at key checkpoints so you can approve or trim results before proceeding.

## Legal and Authorized Use

This is an active reconnaissance tool. It performs port scanning, service
fingerprinting, and web probing that contacts hosts directly. Obviously get permission before running it.

## Prerequisites

- Python 3.10+
- [nmap](https://nmap.org/)
- [bbot](https://github.com/blacklanternsecurity/bbot) (v3.x)
- `dig`, `curl`, `jq` (standard Linux utilities)

Optional (installed by `setup.sh`):

- [masscan](https://github.com/robertdavidgraham/masscan) — fast alive-host discovery (falls back to nmap if missing)
- [gowitness](https://github.com/sensepost/gowitness) (v3.x) — web screenshotting

Optional (manual install, only for bulk reverse DNS — see [Reverse DNS (Stage 3)](#reverse-dns-stage-3)):

- [DuckDB CLI](https://duckdb.org/) — queries THC's monthly bulk rDNS snapshot offline instead of the per-IP API (`curl https://install.duckdb.org | sh`)

## Installation

```bash
git clone <repo-url> auto-scout
cd auto-scout
./setup.sh
cp config.example.yaml config.yaml   # then add your API keys
```

`setup.sh` will:
1. Install Python dependencies (`pip3 install -r requirements.txt`)
2. Install bbot via `pipx` (isolated, since bbot is used as a CLI, not imported)
3. Check for / install masscan and gowitness
4. Create seed file templates in `seeds/`
5. Validate that all required tools are on your PATH

If any tool cannot be installed automatically, the script prints manual
instructions. masscan and gowitness are optional — the pipeline degrades
gracefully without them. bbot is required for stage 6; if `pipx` is not present,
the script tells you how to install both.

## Configuration

Configuration lives in `config.yaml`; it holds your API keys. Copy the provided template and edit your copy:

```bash
cp config.example.yaml config.yaml
```

### API Keys

```yaml
api_keys:
  whoxy: "your-whoxy-api-key"       # Required for stage 4 (reverse WHOIS)
  shodan: ""                          # Optional, improves subdomain coverage
  censys_id: ""
  censys_secret: ""
  securitytrails: ""
  virustotal: ""
  github: ""                          # GitHub personal access token
  chaos: ""                           # ProjectDiscovery Chaos API key
```

**Whoxy** is the only key required by the core pipeline. Get one at [whoxy.com](https://www.whoxy.com/). The bbot-related keys (shodan, censys, etc.) are optional and improve subdomain enumeration results in stage 6. Free tiers are available for most.

### Review Gate Mode

```yaml
review:
  mode: "halt"    # "halt" (default) or "auto"
```

- **halt** — The pipeline stops when a review is needed, prints the file path to review, and exits cleanly. You edit the file at your leisure, then re-run to continue.
- **auto** — Review files are auto-approved without stopping. Useful for fully unattended runs once you trust your seed data and exclusion patterns.

### Port Scan Tuning

```yaml
port_scan:
  masscan_rate: 10000              # Packets/sec for masscan
  masscan_top_ports: 100           # Ports to check during alive-host discovery
  nmap_top_ports: 1000             # Ports for nmap service scan
  nmap_supplemental_ports: []      # Extra ports to always scan, e.g. [8444, 9090, 2222]
  nmap_options: "-sV --open --version-intensity 2 --min-rate 1000"
  nmap_timing: "-T4"
  nmap_max_parallelism: 50
```

`nmap_supplemental_ports` lets you add specific ports of interest without scanning all 65,535. These are scanned in addition to the top-N ports.

### Exclusion Patterns

```yaml
cleanup:
  excluded_domain_patterns:
    - '\.akamai\.net$'
    - '\.cloudfront\.net$'
    - '\.amazonaws\.com$'
    # Add patterns here for domains that should always be removed
  parking_indicators:
    - "parked free"
    - "godaddy"
    - "this domain is for sale"
    # Strings in HTTP response bodies that indicate a parked domain
```

These are applied automatically during stage 5 (cleanup). Domains matching `excluded_domain_patterns` are removed. Domains whose HTTP response contains any `parking_indicators` string are flagged as parked and removed.

Additional exclusions live in the `seeds/out_of_scope_*.txt` files (see [Seed Files](#seed-files)). `out_of_scope_domains.txt` holds regex patterns applied during cleanup.

### Reverse DNS (Stage 3)

Stage 3 has two interchangeable backends, selected with `--rdns-mode` (default `api`). Both write the same `domains_review.txt` / `rdns_raw.json` outputs, so downstream stages don't care which you used.

#### API mode (default)

```yaml
reverse_dns:
  base_url: "https://ip.thc.org"
  page_size: 100
  request_delay_seconds: 2.0       # Seconds between requests (THC refills 0.5 req/s)
  progress_save_interval: 50       # Save checkpoint every N IPs
  max_retries_on_429: 6            # Per-IP retries with exponential backoff on HTTP 429
  max_consecutive_failures: 5      # Abort and save if this many IPs fail in a row
```

Queries the ip.thc.org API one IP at a time. The API rate limit is 250 requests, replenishing at 0.5/sec, so the default 2-second delay stays well within limits. A full scan of a large range can take many hours; the stage saves progress checkpoints so it can resume if interrupted.

#### Bulk mode (`--rdns-mode bulk`)

For large scopes, query THC's monthly bulk snapshot locally with DuckDB instead of the API — no rate limit, minutes-to-hours instead of ~a day — at the cost of freshness (the snapshot is monthly, not live). Coverage matches the API scan: it expands the same stage-2 CIDRs to the same target IPs.

> **Disk space:** the snapshot is large. Budget roughly **~51GB** for the compressed download, **~79GB** for the decompressed parquet, and **~130GB free** during decompression (both files exist at once). You can delete the `.gz` once `gunzip` finishes to reclaim the compressed copy. The decompressed `~79GB` parquet must remain on disk for every run that uses bulk mode.

```yaml
reverse_dns:
  bulk:
    duckdb_bin: "duckdb"           # Path to the DuckDB CLI binary
    parquet_path: ""               # Path to the DECOMPRESSED rdns-*.parquet
    ip_column: ""                  # Auto-detected from the parquet schema when empty
    domain_column: ""              # Auto-detected when empty
    max_expanded_ips: 20000000     # Safety cap on the expanded target-IP set
    query_timeout_seconds: 7200    # DuckDB scan can take a while on a ~79GB file
```

One-time setup:

1. **Get the snapshot.** THC publishes it gzipped on Hugging Face (`rdns-<month>.parquet.gz`, ~51GB compressed / ~79GB uncompressed). DuckDB can't read a gzipped parquet, so decompress it first (needs ~130GB free during decompression):
   ```bash
   gunzip rdns-oct.parquet.gz        # -> rdns-oct.parquet
   ```
2. **Install the DuckDB CLI:**
   ```bash
   curl https://install.duckdb.org | sh
   ```
3. **Point config at the file** via `reverse_dns.bulk.parquet_path`, or pass `--parquet` when running the stage standalone.

Then run the pipeline with `./run.sh --rdns-mode bulk`.

## Seed Files

Seed files live in `seeds/` and are the manual inputs that drive the pipeline. One entry per line; lines starting with `#` are comments.

| File | Purpose | Required |
|------|---------|----------|
| `corporations.txt` | Corporation names to search for ASNs | Yes |
| `domains.txt` | Known root domains for the target | Yes |
| `whois_names.txt` | Registrant names for reverse WHOIS lookups | No |
| `whois_orgs.txt` | Company/organization names for reverse WHOIS | No |
| `whois_emails.txt` | Registrant email addresses for reverse WHOIS | No |
| `out_of_scope_domains.txt` | Regex patterns for domains to always exclude | No |
| `out_of_scope_terms.txt` | Substrings that mark a discovered domain or ASN as out of scope | No |
| `out_of_scope_asns.txt` | ASNs to exclude from discovery (e.g. `AS14618`) | No |

### Example seed files

**corporations.txt**
```
Acme Corporation
Acme Holdings LLC
Acme International
```

**domains.txt**
```
acme.com
acmecorp.net
acme-holdings.com
```

**whois_names.txt**
```
John Smith
Jane Doe
```

**whois_orgs.txt**
```
Acme Corporation
ACME CORP
Acme Holdings LLC
```

**whois_emails.txt**
```
domains@acme.com
admin@acmecorp.net
```

**out_of_scope_domains.txt**
```
# Regex patterns, one per line
\.example\.com$
retired-brand\.com$
```

**out_of_scope_terms.txt**
```
# Substrings, one per line
staging
internal-test
```

**out_of_scope_asns.txt**
```
# ASNs to exclude, one per line
# AS14618
```

Tips for building seed data:
- Search Crunchbase, SEC filings, OpenCorporates, Wikipedia, and LinkedIn for subsidiary names and alternate corporation names.
- Include common variations (LLC, Inc., Corp, abbreviations).
- WHOIS seeds come from examining existing WHOIS records for known domains — look for registrant names, org names, and emails that are shared across the target's portfolio.

## Usage

### Full Pipeline Run

```bash
./run.sh
```

Runs all 9 stages in order, using today's date as the run directory name. The pipeline halts at each review gate (stages 2, 3, and 4).

### Resume After Review

After editing a review file and saving the approved version, re-run:

```bash
./run.sh --date 2026-10-29
```

Completed stages are skipped. If a stage was waiting for review and the approved file now exists, it picks up from there.

### Run Specific Stages

```bash
# Resume from a specific stage (skips earlier completed stages)
./run.sh --from-stage s5_cleanup --date 2026-10-29

# Run only one stage
./run.sh --only s7_portscan --date 2026-10-29

# Run stages 1 through 5
./run.sh --through s5_cleanup
```

### Skip Reviews (Unattended Mode)

```bash
./run.sh --review-mode auto
```

All review gates are auto-approved. Useful once you've validated your seeds and exclusion patterns.

### Reverse DNS: API vs Bulk

Stage 3 defaults to the per-IP ip.thc.org API. For large IP ranges, use the offline bulk backend instead (requires DuckDB and THC's monthly parquet snapshot — see [Reverse DNS (Stage 3)](#reverse-dns-stage-3) for setup):

```bash
./run.sh --rdns-mode bulk
```

`--rdns-mode api` (default) uses the live API; `--rdns-mode bulk` queries the local snapshot. Both feed the same review gate and downstream stages.

### CLI Reference

```
./run.sh [OPTIONS]

Options:
  --config PATH          Path to config file (default: config.yaml)
  --date YYYY-MM-DD      Run date / directory name (default: today)
  --from-stage STAGE     Resume from this stage
  --only STAGE           Run only this stage
  --through STAGE        Run stages 1 through this stage
  --review-mode MODE     "halt" (default) or "auto"
  --rdns-mode MODE       Stage 3 backend: "api" (default, per-IP ip.thc.org)
                         or "bulk" (local DuckDB query over THC's snapshot)

Stage names:
  s1_seeds        Validate and snapshot seed files
  s2_asn          ASN discovery via asndb.network
  s3_rdns         Reverse DNS via ip.thc.org API or bulk snapshot
  s4_rwhois       Reverse WHOIS via Whoxy API
  s5_cleanup      Merge, deduplicate, parking detection
  s6_subdomains   Passive subdomain enumeration (bbot)
  s7_portscan     Port scanning (masscan + nmap)
  s8_web          Web screenshotting (gowitness)
  s9_extras       DNS security checks + Google dorks
```

## Pipeline Stages

### Stage 1: Seeds (`s1_seeds`)

Validates that all required seed files exist and are non-empty. Copies them into the run directory (`runs/<date>/seeds/`) so each run is self-documenting.

### Stage 2: ASN Discovery (`s2_asn`)

Downloads the [asndb.network](https://asndb.network/) ASN-to-organization and IP-to-ASN datasets. Searches for corporation name matches (case-insensitive substring) and extracts all CIDR prefixes for matched ASNs.

**Review gate** — Produces `asns_review.json` listing each matched ASN with its description, matched corporation, prefix count, and an `"include": true` flag. Set `"include": false` for out-of-scope ASNs and save as `asns_approved.json`.

**Output** — `ip_ranges.txt` containing all CIDR blocks for approved ASNs.

### Stage 3: Reverse DNS (`s3_rdns`)

Queries ip.thc.org for each IP in the ranges from stage 2 to find hosted domains. Supports resuming from checkpoints for large IP ranges.

Two backends are available via `--rdns-mode` (see [Reverse DNS (Stage 3)](#reverse-dns-stage-3)): `api` (default) hits the per-IP ip.thc.org API; `bulk` queries THC's monthly bulk snapshot locally with DuckDB, which avoids the API rate limit for large scopes. Both produce identical outputs.

**Review gate** — Produces `domains_review.txt` with all discovered domains (pre-filtered against exclusion patterns). Remove out-of-scope domains and save as `domains_approved.txt`.

### Stage 4: Reverse WHOIS (`s4_rwhois`)

Queries the Whoxy API using three search types:
- **By name** — registrant names from `whois_names.txt`
- **By company** — organization names from `whois_orgs.txt`
- **By email** — registrant emails from `whois_emails.txt`

**Review gate** — Same format as stage 3. Review `domains_review.txt`, save as `domains_approved.txt`.

### Stage 5: Cleanup (`s5_cleanup`)

Merges domains from seeds, stage 3, and stage 4. Deduplicates, applies exclusion patterns, and runs threaded parking page detection (HTTP checks against configurable indicators). Domains that time out are kept — they may be internal or VPN-only.

**Output** — `domains_final.txt`, the master domain list used by all subsequent stages.

### Stage 6: Subdomain Enumeration (`s6_subdomains`)

Runs bbot in passive-only mode against every domain in `domains_final.txt`. Processes domains in batches (default 20) to manage memory. API keys from `config.yaml` are passed to bbot modules for better coverage.

**Output** — `subdomains.txt` and `subdomains_by_domain.json`.

### Stage 7: Port Scanning (`s7_portscan`)

1. Resolves all subdomains and domains to IPs, combines with ASN IP ranges
2. **masscan** — scans top 100 ports to identify alive hosts (requires sudo; falls back to nmap ping scan if unavailable)
3. **nmap** — runs a service scan (`-sV`, configurable) against alive hosts on top 1000 ports + any supplemental ports
4. Converts nmap XML to an Excel workbook with three sheets: Hosts, Services, and Summary

**Output** — `nmap_results.xml`, `nmap_results.gnmap`, `port_scan_results.xlsx`

### Stage 8: Web Analysis (`s8_web`)

Parses nmap XML for any service nmap identified as HTTP-based (by service name or product — e.g., Apache, nginx, IIS) regardless of port number, and runs gowitness to screenshot each one. A configurable fallback port list is used only for open ports where nmap couldn't fingerprint the service. Produces an SQLite database browsable with gowitness's built-in web viewer.

**Output** — `gowitness.sqlite3`, `screenshots/`

To browse results:
```bash
gowitness report server --db-uri sqlite:///path/to/runs/<date>/s8_web/gowitness.sqlite3 --screenshot-path /path/to/runs/<date>/s8_web/screenshots
```

### Stage 9: Extras (`s9_extras`)

- **DNS Security** — Checks SPF, DMARC, and DKIM records for every domain. Flags missing records, permissive SPF (`+all`, `~all`), and unenforced DMARC (`p=none`). Output: `dns_security.json`.
- **Google Dorks** — Generates dork queries per domain and corporation targeting exposed files, admin panels, directory listings, and backups. Output: `dorks.txt`, ready to paste into a browser.

## Output Structure

Each run creates a timestamped directory:

```
runs/2026-10-29/
├── run.log              # Full pipeline log
├── state.json           # Stage completion status
├── seeds/               # Snapshot of seed files used
├── s2_asn/
│   ├── asns_raw.json
│   ├── asns_review.json
│   ├── asns_approved.json
│   └── ip_ranges.txt
├── s3_rdns/
│   ├── rdns_raw.json
│   ├── domains_review.txt
│   └── domains_approved.txt
├── s4_rwhois/
│   ├── rwhois_raw.json
│   ├── domains_review.txt
│   └── domains_approved.txt
├── s5_cleanup/
│   ├── all_domains_raw.txt
│   ├── domains_deduped.txt
│   ├── parking_check.json
│   └── domains_final.txt
├── s6_subdomains/
│   ├── bbot_output/
│   ├── subdomains.txt
│   └── subdomains_by_domain.json
├── s7_portscan/
│   ├── scan_targets.txt
│   ├── masscan_alive.txt
│   ├── nmap_results.xml
│   ├── nmap_results.gnmap
│   └── port_scan_results.xlsx
├── s8_web/
│   ├── web_targets.txt
│   ├── gowitness.sqlite3
│   └── screenshots/
└── s9_extras/
    ├── dns_security.json
    └── dorks.txt
```

`state.json` tracks which stages have completed, so re-running the pipeline skips finished work and resumes from where it left off.

## Typical Workflow

```bash
# 1. Update seed files if the target scope has changed
vim seeds/corporations.txt

# 2. Start the pipeline
./run.sh

# 3. Pipeline halts at stage 2 — review ASN matches
#    Edit asns_review.json, set "include": false for out-of-scope ASNs
#    Save as asns_approved.json
cp runs/2026-10-29/s2_asn/asns_review.json runs/2026-10-29/s2_asn/asns_approved.json
vim runs/2026-10-29/s2_asn/asns_approved.json
./run.sh --date 2026-10-29

# 4. Pipeline halts at stage 3 — review reverse DNS domains
vim runs/2026-10-29/s3_rdns/domains_review.txt
cp runs/2026-10-29/s3_rdns/domains_review.txt runs/2026-10-29/s3_rdns/domains_approved.txt
vim runs/2026-10-29/s3_rdns/domains_approved.txt
./run.sh --date 2026-10-29

# 5. Pipeline halts at stage 4 — review reverse WHOIS domains
#    Same pattern: edit review file, save as approved, re-run

# 6. Stages 5-9 run without stopping
#    Cleanup → subdomain enum → port scan → web screenshots → extras

# 7. Review outputs
#    - Open port_scan_results.xlsx for the service inventory
#    - Browse gowitness results in the web viewer
#    - Check dns_security.json for mail security issues
#    - Use dorks.txt for manual Google dorking
```

## Network and Proxying

**Do not use proxychains or a SOCKS/HTTP proxy with this pipeline.** Several tools (masscan, nmap SYN scans, `dig`) use raw sockets or UDP, which bypass application-layer proxies entirely. Your traffic will leak around the proxy without warning.

If you need to run scans from a non-residential IP (recommended), you have two options:

- **Run on a cloud VPS directly.** Install the pipeline on a cheap VPS and run it there. The stage isolation makes a split workflow easy — run stages 1-5 (OSINT, no target contact) locally, `rsync` the run directory to the VPS, then run `./run.sh --from-stage s6_subdomains --date <date>` remotely and `rsync` results back.
- **Use a WireGuard VPN to a cloud VPS.** A WireGuard tunnel operates at the network layer, so it captures all traffic including raw sockets. You can use a Linux network namespace to scope the tunnel to only the pipeline's traffic. This is more setup initially but lets you run everything from one machine.

## Notes

- **masscan requires root** for raw socket access. The pipeline will prompt for sudo or fall back to an nmap ping scan if sudo is unavailable.
- **Large IP ranges** (e.g., a /16 with 65K IPs) can take many hours in stage 3 due to ip.thc.org rate limits. The stage saves progress checkpoints and resumes where it left off if interrupted.
- **Whoxy API credits** are logged before and after stage 4. The `micro` mode uses the fewest credits per query. Monitor your balance at [whoxy.com](https://www.whoxy.com/).
- The asndb.network datasets are cached locally in `.cache/asndb/` and re-downloaded only if older than 24 hours.
