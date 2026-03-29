# sqli-recon

Active SQL injection surface discovery tool. Finds the doors for sqlmap to pick the locks.

Crawls a target site, analyzes JavaScript, discovers hidden parameters, detects the technology stack, confirms injectable params via error detection, and generates sqlmap-ready output files.

## Install

```bash
git clone https://github.com/Krytical13/sqli-recon.git
cd sqli-recon
./setup.sh
```

For headless SPA crawling (optional, adds ~200MB):
```bash
./setup.sh --with-headless
```

## Usage

```bash
# Full scan — just give it a URL
./scan -u https://target.com

# Via Tor (auto-configures timeout, rate limit, SSL)
./scan -u https://target.com --tor

# With authentication
./scan -u https://target.com --login "admin:password123"
./scan -u https://target.com --cookie "session=abc123; token=xyz"

# Fast recon only (no fuzzing, no API brute)
./scan -u https://target.com --quick

# Custom output directory
./scan -u https://target.com -o ./results

# Resume interrupted scan
./scan -u https://target.com -o ./results --resume
```

## What it does

The default scan runs every phase automatically:

| Phase | What it does |
|-------|-------------|
| **Probe** | Connects to target, fingerprints technology stack |
| **Auth** | Auto-discovers login form, handles CSRF, authenticates (if `--login`) |
| **Crawl** | BFS spider with surface dedup, form/link/path param extraction |
| **Platform injection** | Adds platform-specific high-value endpoints (MyBB, WordPress, etc.) |
| **Headless** | Renders JS-heavy pages, captures XHR/fetch API calls (if `--headless`) |
| **API brute** | Tests 105 common API paths |
| **JS analysis** | Parses JavaScript files for hidden endpoints, POST JSON bodies |
| **Param fuzz** | Discovers hidden parameters via response differentials |
| **Header injection** | Tests Referer, X-Forwarded-For, Host headers for SQLi |
| **GraphQL** | Introspection query to map all arguments |
| **Response analysis** | Identifies endpoints returning DB-row-shaped data |
| **Classification** | Scores every parameter by injection likelihood |
| **Error detection** | Sends `'` to high-scoring params, checks for DB error strings |
| **Second-order hints** | Pairs store points (forms) with render points (admin pages) |

## Output

Each scan produces:

- `sqlmap_urls.txt` — URLs with `*` injection markers (for `sqlmap -m`)
- `requests/` — Individual HTTP request files (for `sqlmap -r`)
- `sqlmap_commands.sh` — Pre-built sqlmap commands with platform-specific flags
- `report.json` — Full findings in JSON
- `report.html` — Visual HTML report (dark theme, self-contained)

## Platform intelligence

When a specific CMS/framework is detected, the scan adapts:

| Platform | Behavior |
|----------|----------|
| **MyBB** | Injects 19 priority endpoints, `--dbms=MySQL --level=3 --tamper=space2comment` |
| **WordPress** | Injects 20 WP endpoints (wp-json, xmlrpc, admin-ajax), `--dbms=MySQL` |
| **phpBB** | Targets viewtopic.php, memberlist.php, `--dbms=MySQL --level=3` |
| **Drupal** | Checks jsonapi, node endpoints, `--dbms=MySQL` |
| **ASP.NET/IIS** | Targets .aspx paths, `--dbms=MSSQL` |
| **Django/Rails** | Reduces risk scores (ORM defaults to parameterized queries) |

## Scoring

Each parameter gets a score from 0.0 to 1.0:

- **0.7+ HIGH** — confirmed injectable (DB error detected) or very strong signals
- **0.4-0.7 MEDIUM** — likely injectable (ID params, sort/search/filter, auth fields)
- **<0.4 LOW** — possible but less likely

Scoring factors: parameter name, location (query/body/json/path/header), value type, technology stack, endpoint type, response content patterns.

## Tor support

`--tor` auto-configures everything:
- Auto-detects local SOCKS port (9050 or 9150)
- Falls back to system-level Tor (Whonix, Tails) if no SOCKS port found
- Sets timeout=60s, rate-limit=1.0s, SSL verification off

## Also included: infra_map

Recursive domain/IP/cert relationship mapper:

```bash
./map example.com                    # Map from a domain
./map 93.184.216.34                  # Map from an IP
./map example.com --depth 3 --tor   # Deep map via Tor
```

Free sources: crt.sh, DNS, HackerTarget, Wayback Machine, BGPView, WHOIS.
Optional: Shodan + Censys API keys for deeper results (`./map --setup-keys`).

## Architecture

```
sqli_recon/
├── cli.py             # Orchestration + CLI
├── http_client.py     # HTTP client with Tor/proxy/WAF/CAPTCHA handling
├── auth.py            # Auto-login, CSRF, session management
├── crawler.py         # BFS web spider with surface dedup
├── js_analyzer.py     # JS endpoint extraction + POST JSON detection
├── headless.py        # Optional Playwright-based SPA crawler
├── param_finder.py    # Hidden parameter fuzzing
├── intelligence.py    # Error detection, tech fingerprint, GraphQL, headers, 2nd-order
├── classifier.py      # SQLi likelihood scoring with deduplication
├── output.py          # sqlmap URL/request/command generation
├── report.py          # HTML report generator
├── checkpoint.py      # Scan state save/resume
├── wordlists.py       # Parameter + API path wordlists
└── models.py          # Data models (Endpoint, Parameter, Finding)

infra_map/
├── cli.py             # Infrastructure mapper CLI
├── graph.py           # Entity relationship graph
├── mapper.py          # Recursive expansion engine
├── sources.py         # Data sources (free + optional Shodan/Censys)
├── config.py          # API key configuration
└── output.py          # Tree view, JSON, domain/IP list export
```
