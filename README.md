# recon.py

```
 Full Automated Reconnaissance Framework  v6.0
```

**Recon.py** is a fully automated web reconnaissance and vulnerability scanning framework written in Python 3. It orchestrates more than 30 external tools across a structured pipeline covering subdomain enumeration, URL collection, JS analysis, parameter discovery, WAF detection, active exploitation tests and AI-assisted reporting — all from a single command.

> **Use only on systems for which you have explicit written authorization.**

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Pipeline](#pipeline)
- [Scan Profiles](#scan-profiles)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration Reference](#configuration-reference)
- [Output Structure](#output-structure)
- [AI Features](#ai-features)
- [Security & Ethics](#security--ethics)
- [Changelog](#changelog)

---

## Overview

Recon.py was designed around three principles: **robustness**, **scalability**, and **signal-to-noise ratio**. Every component that talks to external tools is routed through a centralized execution layer that handles timeouts, ANSI stripping, error classification, and disk-backed output to prevent memory exhaustion on large scans.

The framework is self-contained. It auto-detects which optional tools are installed, adapts its scan intensity based on observed WAF responses, and can persist findings across sessions using SQLite with WAL mode and a dedicated insert worker to avoid race conditions under high concurrency.

Anthropic's Claude API is optionally integrated at multiple points: AI attack planning, intelligent vulnerability triage, WAF bypass payload generation, and natural-language executive summary generation for non-technical stakeholders.

---

## Architecture

### ToolRunner

All subprocess calls pass through a single `ToolRunner` instance. It standardizes:

- Return code normalization (`-1` timeout, `-2` binary not found, `-3` OSError)
- Automatic ANSI escape strip from stdout/stderr
- Configurable per-call timeout
- Direct-to-disk output mode for memory-intensive tools (nuclei, katana, ffuf)
- Dry-run passthrough that skips actual execution while preserving the call graph

### CircuitBreaker

Each scan module (XSS, SQLi, LFI, etc.) is wrapped by a `CircuitBreaker`. After 3 consecutive failures, the circuit opens and the module is skipped for the remainder of the run. This prevents silent loops where broken tools produce empty files that look like clean scan results.

### SQLite Persistence

Findings are written to a SQLite database using WAL journal mode and a dedicated background thread that drains an `asyncio.Queue`-style `queue.Queue`. This eliminates write contention when dozens of scan threads try to persist findings simultaneously.

Tables: `subdomains`, `vulns`, `blocked_ips`, `scan_history`.

### Rate & Feedback System

The framework tracks HTTP 429 responses at two levels:

- **Global backoff** — shared across all threads, automatically increases on repeated 429s and decays on successful responses.
- **Per-host backoff** — isolated to the specific host returning 429s, leaving other hosts at full speed.

Both counters are protected by dedicated threading locks (a v6 fix for race conditions under GIL).

### URL Deduplication

Before active scans begin, `url_signature()` normalizes each URL (sorted query params, stripped values) to produce a structural fingerprint. `deduplicate_by_signature()` then removes semantically identical URLs, reducing scan load by approximately 80% on typical targets.

### Payload Feedback Loop

Every HTTP response feeds back into the payload selection engine. Payloads that consistently return 403 are recorded (keyed by normalized prefix) and deprioritized in subsequent requests, reducing noise and WAF signature burns.

---

## Pipeline

The scan executes in strict step order. Each step writes its output to a defined file so downstream steps can consume it independently.

| Step | Name | Tools |
|------|------|-------|
| 00 | Health Check | binary validation, API ping, SQLite probe |
| 01 | Subdomain Enumeration | subfinder, amass, assetfinder, findomain, dnsx, shuffledns |
| 02 | Passive Intelligence | Shodan API, crt.sh, SecurityTrails |
| 03 | Alive Hosts | httpx |
| 03b | SPA Crawling | Playwright (headless) |
| 04 | Port Scanning | naabu |
| 05 | Screenshots | gowitness |
| 05b | Subdomain Takeover | subzy |
| 05c | Technology Profiler | whatweb, header analysis |
| 05d | Cloud Recon | AWS S3, GCS, Azure Blob, Kubernetes, Docker API |
| 06 | URL Collection | waybackurls, gau, katana |
| 07 | URL Filtering | uro, category split (php/api/admin/js) |
| 07b | WAF Detection | wafw00f, manual header fingerprinting |
| 08 | JS Analysis | regex secrets, TruffleHog v3, JWT validation |
| 09 | Parameter Extraction | uro, qsreplace, arjun, httpx alive check |
| 10 | GF Patterns | gf (xss/sqli/lfi/ssrf/redirect/ssti/idor/cors) |
| 11 | Directory Brute-force | ffuf |
| 12 | 403 Bypass | header/path manipulation techniques |
| 13 | CORS | origin reflection, null origin, subdomain trust |
| 14 | Security Headers | strict-transport, csp, x-frame, referrer-policy |
| 15 | Sensitive Files | backup, config, git, env file exposure |
| 16 | Metadata Harvesting | exiftool, document author/GPS leakage |
| 17 | XSS | dalfox, manual reflected, DOM, header injection |
| 18 | SQL Injection | ghauri, error-based, blind, POST body |
| 19 | LFI / Path Traversal | payload list, context validation |
| 19b | Open Redirect | parameter-based, header-based |
| 19c | NoSQL Injection | MongoDB operator injection |
| 19d | SSTI | Jinja2/Twig/Freemarker detection |
| 19e | SSRF | interactsh callback, internal IP probing |
| 19f | XXE | external entity, blind OOB |
| 19g | IDOR | numeric/UUID parameter enumeration |
| 19h | CRLF Injection | header injection via CRLF sequences |
| 19i | Host Header Injection | X-Forwarded-Host, X-Host manipulation |
| 19j | GraphQL | introspection, batch query abuse |
| 20 | Nuclei | CVE templates, misconfigs, exposures |
| 20b | AI Triage | Claude API severity classification |
| 20c | Credential Leak | HaveIBeenPwned API |
| 20d | PoC Generator | auto-generated Python scripts per finding |
| 20e | Executive Summary | Claude API non-technical report |
| 20f | Output Encryption | GPG AES-256 on sensitive files |

---

## Scan Profiles

Four profiles control thread counts, depth limits, and timing behavior. They can be selected via flags or overridden granularly with individual limit arguments.

| Profile | Flag | Threads | Intent |
|---------|------|---------|--------|
| Normal | (default) | 100 | Balanced coverage and speed |
| Stealth | `--stealth` | 20 | Low-noise, jitter enabled, WAF evasion on, extended delays |
| Aggressive | `--aggressive` | 200 | Maximum coverage, high concurrency, extended payload lists |
| Deep | `--deep` | 100 | Increased crawl depth, larger URL/param/JS limits |

Dry-run mode (`--dry-run`) simulates the entire pipeline without sending any requests to the target. Useful for validating configuration, scope, and tool availability before an authorized engagement.

---

## Prerequisites

### Python

- Python 3.9+
- No third-party Python packages required (stdlib only)

### Optional Python packages (for Playwright mode)

```
pip install playwright
playwright install chromium
```

### External Tools

The following tools extend functionality when installed. Recon.py auto-detects availability and skips modules for tools that are absent.

**Core (strongly recommended)**

```
subfinder   httpx       katana      gau         waybackurls
nuclei      dalfox      ffuf        uro          qsreplace
gf          dnsx        wafw00f     gowitness    naabu
```

**Optional but valuable**

```
amass       assetfinder findomain   shuffledns   subzy
arjun       trufflehog  sqlmap      ghauri       exiftool
gpg         interactsh  whatweb
```

---

## Installation

### Automated

The `--install` flag attempts to install all Go-based tools, Python dependencies, and GF patterns automatically.

```bash
python3 recon.py --install
```

This requires Go 1.21+ in `PATH` and will run `go install` for each tool. Python tools and Playwright are installed via pip.

### Manual

Install Go tools individually, for example:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/gf@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/shenwei356/uro@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/sensepost/gowitness@latest
go install github.com/PentestPad/subzy@latest
```

---

## Usage

### Basic

```bash
python3 recon.py target.com
```

### Common flags

```bash
# Multithreaded with deep crawl
python3 recon.py target.com --threads 200 --deep

# AI-assisted planning + OODA agent
python3 recon.py target.com --plan --agent --api-key $ANTHROPIC_API_KEY

# Headless SPA crawl (React, Vue, Angular)
python3 recon.py target.com --playwright

# Real-time alerts on Discord/Slack/Telegram
python3 recon.py target.com --webhook-url https://hooks.slack.com/...

# Restrict scope and simulate (no requests sent)
python3 recon.py target.com --whitelist target.com --dry-run

# Encrypt sensitive output files at end of scan
python3 recon.py target.com --encrypt-output --encrypt-pass 'YourPassphrase'

# Watcher mode: re-runs scan on interval, reports only new findings
python3 recon.py target.com --watch --watch-interval 3600

# Stealth profile with Shodan passive intel
python3 recon.py target.com --stealth --shodan-key $SHODAN_API_KEY

# Live HTML dashboard during scan
python3 recon.py target.com --live-dashboard --dashboard-port 8765
```

### Full options reference

```
positional:
  domain                   Target domain

scan control:
  --threads N              Concurrent threads (default: 100)
  --deep                   Increased crawl depth and payload limits
  --stealth                Low-noise profile: jitter, WAF evasion, reduced speed
  --aggressive             Maximum coverage and concurrency
  --skip-scans             Skip all active exploitation steps
  --skip-screenshots       Skip gowitness screenshots
  --dry-run                Simulate without sending requests
  --no-adaptive            Disable adaptive scan adjustment
  --timeout N              HTTP request timeout in seconds (default: 10)
  --curl-delay N           Delay between curl calls in seconds
  --xss-deadline N         Per-URL time limit for XSS manual scans (default: 45s)

intelligence:
  --plan                   Enable AI attack planner (requires --api-key)
  --agent                  Enable OODA agent with function calling
  --api-key KEY            Anthropic API key (or set ANTHROPIC_API_KEY)
  --shodan-key KEY         Shodan API key for passive intelligence
  --playwright             Enable headless SPA crawling via Playwright
  --no-passive-intel       Skip Shodan and passive lookups

limits (per-module URL/param caps):
  --limit-cors N           CORS check limit (default: 50)
  --limit-headers N        Header check limit (default: 30)
  --limit-lfi N            LFI payload limit (default: 30)
  --limit-idor N           IDOR test limit (default: 30)
  --limit-sqli N           SQLi URL limit (default: 30)
  ...

output:
  --sqlite-db PATH         Path to SQLite persistence database
  --no-delta               Disable delta mode (report all, not just new)
  --encrypt-output         Encrypt sensitive output files with GPG
  --encrypt-pass PASS      GPG passphrase for encryption
  --live-dashboard         Start local HTTP server for live HTML report
  --dashboard-port N       Dashboard port (default: 8765)
  --webhook-url URL        Webhook for real-time Discord/Slack/Telegram alerts

scope & safety:
  --whitelist DOMAINS      Comma-separated allowed domains (safe mode)
  --hibp-key KEY           HaveIBeenPwned API key for credential leak check

watcher:
  --watch                  Watcher mode: repeat scan on interval
  --watch-interval N       Seconds between watcher runs (default: 3600)

setup:
  --install                Install all dependencies automatically
```

---

## Configuration Reference

### Environment variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Anthropic Claude API key |
| `SHODAN_API_KEY` | Shodan API key |
| `RECON_WORDLIST` | Path to custom wordlist (overrides built-in) |
| `RECON_WEBHOOK_URL` | Default webhook URL |

Variables can be set in a `.env` file in the working directory or in `~/.recon.env`. Both are loaded automatically at startup.

### .env example

```env
ANTHROPIC_API_KEY=sk-ant-...
SHODAN_API_KEY=...
RECON_WORDLIST=/opt/wordlists/SecLists/Discovery/Web-Content/raft-large-words.txt
RECON_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

---

## Output Structure

Each scan creates a timestamped directory under the current working directory.

```
target.com_YYYYMMDD_HHMMSS/
├── disc/
│   ├── subdomains.txt          All discovered subdomains
│   ├── alive.txt               HTTP-responding hosts
│   └── takeover.txt            Subdomain takeover candidates
├── urls/
│   ├── urls_all.txt            Raw merged URL list
│   ├── urls_clean.txt          Deduplicated, filtered URLs
│   ├── urls_php.txt            PHP endpoints
│   ├── urls_api.txt            API endpoints
│   ├── urls_admin.txt          Admin/dashboard paths
│   └── urls_js.txt             JavaScript files
├── params/
│   ├── params.txt              Unique parameterized URLs
│   ├── params_alive.txt        Parameterized URLs with live responses
│   ├── params_fuzz.txt         FUZZ-replaced for direct tool use
│   ├── param_names.txt         Parameter frequency analysis
│   └── arjun_raw.txt           Parameters discovered via Arjun
├── js/
│   ├── js_secrets.txt          Potential secrets (API keys, tokens, passwords)
│   ├── js_secrets_validated.txt JWT expiry status, token validation
│   ├── js_endpoints.txt        Endpoints extracted from JS bundles
│   └── trufflehog.txt          TruffleHog v3 JSON output
├── vulns/
│   ├── xss.txt / sqli.txt ...  GF pattern matches per vuln class
│   └── *.txt                   Per-category URL lists
├── scans/
│   ├── dalfox.txt              Confirmed XSS (dalfox)
│   ├── xss_manual.txt          Reflected XSS (manual)
│   ├── xss_dom.txt             DOM XSS candidates
│   ├── sqli_confirmed.txt      Confirmed SQL injection
│   ├── sqli_error_based.txt    Error-based SQLi
│   ├── sqli_blind.txt          Blind SQLi candidates
│   ├── lfi_results.txt         LFI confirmed paths
│   ├── ssrf_results.txt        SSRF callbacks
│   ├── ssti_results.txt        SSTI confirmed
│   ├── xxe_results.txt         XXE findings
│   ├── idor_results.txt        IDOR candidates
│   ├── nuclei_critical.txt     Nuclei critical findings
│   ├── nuclei_high.txt         Nuclei high findings
│   └── ...
├── extra/
│   ├── waf_detected.txt        WAF identification per host
│   ├── cors_results.txt        Misconfigured CORS policies
│   ├── header_issues.txt       Missing/weak security headers
│   ├── sensitive_files.txt     Exposed backup/config/git files
│   ├── metadata.txt            Exiftool findings
│   └── cloud_recon.txt         Exposed S3/GCS/Azure/K8s/Docker
├── screenshots/                gowitness captures
├── report/
│   ├── index.html              Self-contained HTML report
│   ├── vuln_urls.txt           All confirmed findings
│   ├── vuln_urls.json          Structured findings (JSON)
│   ├── ai_triage.txt           Claude severity analysis
│   ├── executive_summary.txt   Non-technical AI summary
│   ├── credential_leaks.txt    HaveIBeenPwned results
│   └── poc/
│       ├── poc_xss.py          XSS proof-of-concept script
│       ├── poc_sqli.py         SQLi PoC (sqlmap wrapper)
│       ├── poc_ssrf.py         SSRF PoC (interactsh probe)
│       └── poc_idor.py         IDOR PoC (auth header test)
├── recon.log                   Full timestamped execution log
└── error.log                   Tool-level error log
```

Sensitive files (`js_secrets.txt`, `ai_triage.txt`, `credential_leaks.txt`, etc.) can be encrypted with GPG AES-256 at scan completion using `--encrypt-output`. Originals are removed after encryption.

To decrypt:

```bash
gpg --decrypt report/ai_triage.txt.gpg
```

---

## AI Features

All AI features require an Anthropic API key and use `claude-sonnet-4-20250514`.

### AI Attack Planner (`--plan`)

Before active scans begin, the planner sends discovered tech stack, WAF status, and URL categories to the API. The model returns a prioritized list of attack vectors suited to the identified technologies (e.g., PHP targets get higher-priority LFI payloads; GraphQL endpoints trigger introspection checks first).

### OODA Agent (`--agent`)

When `--agent` is active, the OODA loop (Observe, Orient, Decide, Act) replaces the static sequential pipeline for active scans. The agent receives post-recon context and uses Anthropic function calling to decide which modules to execute, in which order, and with which parameters. It can adapt mid-run based on intermediate findings.

### WAF AI Bypass

When an active scan receives a 403, the framework optionally queries the API for 3 structurally varied bypass payloads. Responses are cached by `(attack_type, WAF vendor)` key so the same question is never asked twice in a single run. This cache is a v6 addition that reduces API cost significantly on targets with consistent WAF behavior.

### AI Triage

After all active scans complete, confirmed findings are sent to the API for severity classification and false-positive filtering. Output includes confidence scores and recommended CVSS ratings.

### Executive Summary

A separate API call generates a plain-language summary for management audiences. The prompt explicitly instructs the model to avoid technical jargon and frame each finding in terms of business impact and risk priority.

---

## Security & Ethics

- **Authorization required.** Running this tool against systems without explicit written authorization is illegal in most jurisdictions. The tool is intended for use during authorized penetration tests, bug bounty engagements (within defined scope), and security assessments of systems you own.
- **Whitelist mode** (`--whitelist target.com`) causes the framework to refuse to scan any hostname not matching the approved list. Use it when working inside a large organization with many subdomains and a defined scope.
- **Dry-run mode** (`--dry-run`) allows full pipeline validation — including AI planning, tool detection, and directory setup — without sending a single request to the target.
- **PoC scripts** are generated with manual execution steps. They are designed as confirmation tools, not attack scripts, and include comments instructing operators not to automate them against production systems.
- **Credential leak data** from HIBP is written to disk only and is never transmitted beyond the HIBP API and optional GPG-encrypted output.

---

## Changelog

### v6.0 — Robustness & Scalability

**Critical fixes**
- Race condition on `_rate_429_count` and `_rate_backoff` — now protected by a dedicated threading lock
- `except Exception: pass` replaced throughout with specific exception types and structured logging
- Circuit Breaker pattern implemented — modules are disabled after 3 consecutive failures
- WAF AI Bypass integrated into XSS/SQLi flow with per-WAF response cache

**Architectural additions**
- `ToolRunner` — centralized subprocess execution (logging, ANSI strip, timeout, disk write)
- `CircuitBreaker` — prevents silent failure loops in broken modules
- `url_signature()` + `deduplicate_by_signature()` — reduces redundant URL processing by ~80%
- `step_initial_health_check()` — validates binaries, API connectivity, and SQLite before any scan step
- WAF AI Bypass cache keyed by `(attack_type, WAF vendor)` — avoids repeated API calls for identical scenarios

### v5.0

- OODA Agent with Anthropic function calling
- Playwright headless crawling for SPA targets
- Native webhook support (Discord, Slack, Telegram)
- WAF AI Bypass (initial implementation)
- Async SQLite insert queue with dedicated worker thread
- `.env` / `RECON_WORDLIST` environment variable support
- `host_throttle()` fix — per-host backoff no longer blocks the global ThreadPoolExecutor

### v4.0

- Cloud reconnaissance: S3, GCS, Azure Blob, Kubernetes API, Docker API
- PoC Generator for confirmed XSS, SQLi, SSRF, IDOR
- Credential leak check via HaveIBeenPwned API
- Executive Summary AI report
- GPG AES-256 output encryption
- Per-host rate limiting
- Live Dashboard (local HTTP server with auto-refresh)
- Whitelist / Safe Mode
- Dry-run mode

### v3.0

- Technology Profiler (stack detection before scan)
- AI Attack Planner
- Payload Feedback Loop (403 tracking, payload deprioritization)
- SQLite persistence with delta mode
- 403 Bypass module
- Metadata Harvesting (exiftool)
- Self-contained HTML report
- Watcher Mode (scheduled re-scan with delta reporting)
- JS Secret Validation (JWT expiry, active token probe)
- GF pattern integration

---

## License

For authorized security testing only. See [LICENSE](LICENSE) for terms.
