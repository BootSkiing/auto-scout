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

Automated external asset enumeration for **authorized** security assessments. Auto-Scout discovers an organization's internet-facing footprint from a handful of seed names/domains, then hands it to active recon — turning "who are they online?" into a reviewed asset inventory with open ports, services, and screenshots.

It runs as nine independent stages. Each reads files and writes files, so any stage can run on its own, and human review gates pause the run at key points so you approve or trim results before anything downstream acts on them.

**Features**

- **Discovery:** ASN lookups ([asndb.network](https://asndb.network/)), reverse DNS ([ip.thc.org](https://ip.thc.org/) — live API or offline bulk snapshot), reverse WHOIS (Whoxy), passive subdomain enumeration (bbot).
- **Active recon:** full-port scanning + service fingerprinting (masscan → nmap), web screenshotting (gowitness), DNS-security checks and Google-dork generation.
- **Control:** human review gates, two-layer scope filtering, resumable stages (and `--force` for clean re-runs), Excel service inventory.

> ⚠️ **Authorized use only.** This is an *active* recon tool — it port-scans, fingerprints services, and probes web apps by contacting hosts directly. Get written permission before running it against anything you don't own.

## Setup

```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv pipx nmap masscan chromium-browser
git clone https://github.com/BootSkiing/auto-scout && cd auto-scout
python3 -m venv . && source bin/activate
./setup.sh                             # installs deps, bbot (pipx), gowitness; creates seed templates
cp config.example.yaml config.yaml     # then add your API keys
```

Requires Python 3.10+, `nmap`, and `dig`/`curl`/`jq`. `setup.sh` installs the optional tools and prints manual steps for anything it can't: masscan and gowitness degrade gracefully if missing, but **bbot is required for stage 6**.

> **bbot PATH:** pipx installs `bbot` to `~/.local/bin`, which isn't on a fresh Ubuntu `PATH`. `run.sh` prepends it automatically; if you call `orchestrator.py` directly, add `~/.local/bin` to your `PATH` (or open a new shell after `setup.sh`).

### Configuration

Everything lives in `config.yaml` (a copy of the fully-commented `config.example.yaml`). The essentials:

- **API keys** — `api_keys.whoxy` is the only key the core pipeline requires ([whoxy.com](https://www.whoxy.com/), free tier available). Shodan / Censys / SecurityTrails / VirusTotal / GitHub / Chaos keys are optional and improve stage-6 subdomain coverage.
- **Review mode** — `review.mode: halt` (default; stop for manual review) or `auto` (unattended, auto-approve).
- **Port scanning** — `port_scan.scan_mode: full` (all 65,535 ports) or `top-ports` (fast); rate, retries, timeouts, and the all-open cap are tunable. See [Stage 7](#stage-7-port-scanning-s7_portscan) and [Gotchas](#gotchas).

### Scope vs. exclusions

Two separate filtering mechanisms:

| Mechanism | What it's for | Matching | Applied in |
|---|---|---|---|
| `seeds/out_of_scope_{domains,terms,asns}.txt` | your explicit scope boundaries | exact (domain + subdomains / term / ASN); case-insensitive | each relevant stage, before work **and** before review |
| `cleanup.excluded_domain_patterns` | shared CDN / DNS-edge / WAF junk (Akamai, Fastly, CloudFront, Cloudflare, Azure CDN/DNS…) | regex, case-insensitive | s3, s4, s5 |

Cloud *hosting* (`*.amazonaws.com` S3/ELB/EC2, `*.azurewebsites.net`, etc.) is deliberately **not** excluded — a target's own assets live there. Every scope removal is logged to `<stage>/scope_removed.json`.

### Seed files

Manual inputs in `seeds/` (one entry per line, `#` for comments); `setup.sh` creates templates.

| File | Purpose | Required |
|---|---|---|
| `corporations.txt` | names to search for ASNs | **yes** |
| `domains.txt` | known root domains | **yes** |
| `whois_{names,orgs,emails}.txt` | reverse-WHOIS search terms | no |
| `out_of_scope_{domains,terms,asns}.txt` | scope exclusions (see above) | no |

Build corporation/WHOIS seeds from Crunchbase, SEC filings, OpenCorporates, and the WHOIS records of domains you already know; include name variants (LLC, Inc., Corp, abbreviations).

## Usage

```bash
./run.sh                               # full run; halts at each review gate (stages 2, 3, 4)
./run.sh --date 2026-10-29             # resume a run: skips completed stages, picks up approved reviews
./run.sh --from-stage s6_subdomains    # resume from a given stage
./run.sh --only s7_portscan            # run a single stage
./run.sh --through s5_cleanup          # run stages 1 through N
./run.sh --review-mode auto            # unattended: auto-approve all review gates
./run.sh --rdns-mode bulk             # stage 3 via offline snapshot instead of the live API
./run.sh --force                       # re-run even completed stages from a clean slate
```

**Review workflow:** in halt mode the run stops at stages 2–4 and prints a `*_review.*` file. Edit it, save it as the matching `*_approved.*` file (e.g. `asns_review.json` → `asns_approved.json`), and re-run with the same `--date`. Completed stages are skipped; a waiting stage picks up from the approved file.

### Options

```
./run.sh [OPTIONS]

  --config PATH          Config file (default: config.yaml)
  --date YYYY-MM-DD      Run directory name (default: today)
  --from-stage STAGE     Resume from this stage
  --only STAGE           Run only this stage
  --through STAGE        Run stages 1 through this stage
  --review-mode MODE     "halt" (default) or "auto"
  --rdns-mode MODE       Stage 3 backend: "api" (default) or "bulk"
  --force                Re-run even completed stages, wiping each stage dir first
                         (approved files and resume progress included)

Stages: s1_seeds  s2_asn  s3_rdns  s4_rwhois  s5_cleanup
        s6_subdomains  s7_portscan  s8_web  s9_extras
```

## Pipeline Stages

### Stage 1: Seeds (`s1_seeds`)
Validates that required seed files exist and are non-empty, and snapshots them into `runs/<date>/seeds/` so each run is self-documenting.

### Stage 2: ASN Discovery (`s2_asn`)
Downloads the asndb.network datasets, matches `corporations.txt` names (case-insensitive substring), and extracts the CIDR prefixes for matched ASNs.
**Review gate:** `asns_review.json` lists each matched ASN (`"include": true`); set `false` to drop one, save as `asns_approved.json`. **Output:** `ip_ranges.txt`.

### Stage 3: Reverse DNS (`s3_rdns`)
Finds domains hosted on the stage-2 IP ranges via ip.thc.org. Two interchangeable backends (`--rdns-mode`): `api` (default, per-IP, rate-limited, resumable) or `bulk` (offline snapshot — see [Bulk reverse DNS](#bulk-reverse-dns-optional)). Both produce identical outputs.
**Review gate:** `domains_review.txt`, pre-filtered against the exclusion patterns and out-of-scope domains → save as `domains_approved.txt`.

### Stage 4: Reverse WHOIS (`s4_rwhois`)
Queries Whoxy by registrant name, organization, and email (`whois_*.txt` seeds).
**Review gate:** same as stage 3 — `domains_review.txt` → `domains_approved.txt`.

### Stage 5: Cleanup (`s5_cleanup`)
Merges domains from seeds + stages 3/4, deduplicates, applies the exclusion patterns and out-of-scope domains, and runs threaded parking-page detection (domains that time out are kept — they may be internal/VPN-only). This is where seed domains get scope-checked and the backstop for anything approved before it was marked out of scope.
**Output:** `domains_final.txt`, the master list for all later stages.

### Stage 6: Subdomain Enumeration (`s6_subdomains`)
Runs bbot passive-only against every domain in `domains_final.txt`, in batches to manage memory, using the configured API keys for coverage. New subdomains are filtered against out-of-scope domains before being written (no human gate here).
**Output:** `subdomains.txt`, `subdomains_by_domain.json`.

### Stage 7: Port Scanning (`s7_portscan`)
1. **Resolution gate** — drops non-host labels (underscore/service records like `_dmarc`, `_acme-challenge`, and the `_wildcard` cert-transparency artifact), resolves the remaining names to IPs (parallel `dig`), and folds in the stage-2 CIDR ranges. Filtered/unresolved names are logged to `resolution_gate.json`.
2. **masscan** — sweeps ports across all target IPs (all 65,535 in `full` mode; top-N in `top-ports`). Its open-ports-per-host results *are* the discovery, so a host whose only open port is uncommon isn't missed, and partial output from an interrupted scan is salvaged.
3. **nmap** — service/version scan run **per host on exactly the ports masscan found open**, grouped by port-set and sharded into batches. Hosts reporting more than `max_open_ports_per_host` open (likely firewall/LB/tarpit) are logged to `filtered_hosts.json` and skipped. Each IP is scanned via one representative hostname so nmap records the name natively; the full name-per-IP map is kept in `ip_hostname_map.json`.
4. Merges the per-batch nmap XML into an Excel workbook (Hosts / Services / Summary).

Re-running always re-scans (no "already done" short-circuit) and clears stale artifacts first. If masscan is unavailable, nmap does discovery itself (slower).
**Output:** `port_scan_results.xlsx` + the JSON/text artifacts above.

### Stage 8: Web Analysis (`s8_web`)
Screenshots every HTTP service nmap identified (by service/product, any port) with gowitness; a fallback port list covers open ports nmap couldn't fingerprint.
**Output:** `gowitness.sqlite3`, `screenshots/`. Browse with:
```bash
gowitness report server --db-uri sqlite:///path/to/runs/<date>/s8_web/gowitness.sqlite3 --screenshot-path /path/to/runs/<date>/s8_web/screenshots
```

### Stage 9: Extras (`s9_extras`)
- **DNS security** — SPF/DMARC/DKIM per domain; flags missing records, permissive SPF (`+all`/`~all`), unenforced DMARC (`p=none`). → `dns_security.json`.
- **Google dorks** — generated per domain/corporation (exposed files, admin panels, listings, backups). → `dorks.txt`.

## Bulk reverse DNS (optional)

Stage 3's default API is rate-limited (hours for large scopes). For big ranges, query THC's monthly snapshot offline with DuckDB instead — no rate limit, same coverage, at the cost of freshness (monthly, not live).

```bash
curl https://install.duckdb.org | sh                   # 1. DuckDB CLI (not proxy-blocked)
curl -L -C - -o rdns.parquet.gz '<huggingface-link>'   # 2. snapshot (~51GB; -C - resumes)
gunzip rdns.parquet.gz                                 # 3. -> ~79GB parquet
# 4. set reverse_dns.bulk.parquet_path in config.yaml, then:
./run.sh --rdns-mode bulk
```

- **Disk:** budget ~130GB free during decompression (both files exist at once); the ~79GB parquet must stay on disk for every bulk run.
- **Hugging Face is Zscaler-blocked** — download off-network and copy the file over. Get the current month's link from THC's [bulk data access page](https://ip.thc.org/docs/bulk-data-access) (the URL path encodes the *release* month, the filename the *data* month — don't assume they match).
- `ip`/`domain` columns auto-detect from the schema; override via `reverse_dns.bulk.{ip,domain}_column` if detection fails.

## Gotchas

- **No proxychains / SOCKS / HTTP proxies.** masscan, nmap SYN scans, and `dig` use raw sockets/UDP that bypass application-layer proxies — your traffic leaks around them silently. To scan from a non-residential IP: run on a cloud VPS directly (stages 1–5 make no target contact, so run those locally and `rsync` the run dir over for 6–9), or route everything through a WireGuard tunnel (network-layer, so it catches raw sockets).
- **masscan needs passwordless sudo.** It's run as `sudo -n masscan`; without it the stage falls back to a much slower direct nmap scan. Full-port scans take hours to days — expected, and `masscan_timeout: null` keeps them from being killed.
- **Scanning from EC2:** bandwidth is *never* the limit for SYN scanning (~tens of Mbps even at high rates). The real ceilings are the **ENA packets-per-second allowance** and **security-group connection tracking** — start `masscan_rate` conservatively and watch the ENA CloudWatch `*_allowance_exceeded` counters. Make scan flows *untracked* (an all-traffic SG rule in both directions) to dodge conntrack drops, and pair `masscan_source_port` with an iptables RST-drop rule so the kernel doesn't reset masscan's probes.
- **Large IP ranges** take many hours in stage 3 (API rate limits) — it checkpoints and resumes; or use bulk mode.
- **Whoxy credits** are logged before/after stage 4 (`micro` mode is cheapest). **asndb datasets** cache in `.cache/asndb/`, re-downloaded after 24h.

## Output

Each run writes to `runs/<date>/` — one subdirectory per stage, plus `run.log` and `state.json`. Highlights:

- `s7_portscan/port_scan_results.xlsx` — the service inventory (Hosts / Services / Summary)
- `s8_web/` — screenshots + browsable gowitness DB
- `s9_extras/` — `dns_security.json`, `dorks.txt`
- each discovery stage — `*_review.*` → `*_approved.*`, plus `scope_removed.json`

`state.json` tracks completion, so re-runs skip finished work and resume at review gates. A re-running stage first clears its own stale/regenerated outputs (keeping approved files and resume progress); `--force` wipes a stage dir entirely for a clean slate.
