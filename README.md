# SpiderFoot Revival

Self-hosted OSINT automation platform. Forked from [SpiderFoot](https://github.com/smicallef/spiderfoot) with a modernized UI, overhauled module ecosystem, and improved developer experience.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.9+-green)](https://www.python.org)
[![Version](https://img.shields.io/badge/version-5.0.2-blue.svg)](CHANGELOG.md)

## What Changed from Upstream

- **Frontend rewrite**: CherryPy/jQuery/Bootstrap replaced with Flask/Tailwind CSS/HTMX/Alpine.js
- **Dark SOC-themed UI** with collapsible sidebar, category-grouped results, and HTMX-driven interactions
- **Module audit**: 11 dead modules removed, 6 broken APIs fixed, 22 new modules added
- **244 total modules** covering passive recon, breach data, threat intel, cloud discovery, and vulnerability scanning
- **BBOT integration**: 4 wrapper modules providing access to 50+ BBOT sources
- **Full REST API** for programmatic scan management and data export

## Quick Start

### Docker (recommended)

```bash
docker build -t spiderfoot-revival .
docker run -p 5001:5001 spiderfoot-revival
```

Visit [http://localhost:5001](http://localhost:5001)

### Docker with persistent storage

```bash
docker run -p 5001:5001 -v /my/data:/var/lib/spiderfoot spiderfoot-revival
```

### Local development

```bash
pip install -r requirements.txt
python sf.py -l 127.0.0.1:5001
```

Requires Python 3.9+.

## Features

- **244 OSINT modules** across passive recon, active scanning, breach data, and threat intelligence
- **Event-driven pipeline** — modules produce and consume typed events, cascading discovery automatically
- **Web UI** — dark theme, real-time scan progress, categorized results, expandable event details
- **REST API** — full scan lifecycle management, JSON/CSV/GEXF export, config import/export
- **CLI mode** — run scans without the web server
- **Correlation engine** — YAML-configurable rules (37 built-in) for cross-referencing findings
- **Docker-first** — Alpine-based image, non-root user, persistent volume support

## Target Types

SpiderFoot can scan:

- Domain / subdomain names
- IP addresses
- Network subnets (CIDR)
- Email addresses
- Phone numbers
- Usernames
- Person / company names
- Bitcoin addresses
- ASNs

## New in v5.0.0

### New Modules (22)

| Module | Source | Auth |
|--------|--------|------|
| Shodan InternetDB | Ports, CVEs, hostnames | Free, no key |
| LeakCheck | Breach database | Free public + pro |
| Hudson Rock | Infostealer intelligence | Free |
| Criminal IP | Threat intel | Free tier with key |
| Netlas.io | Attack surface search | Free tier with key |
| Validin | DNS history, CT logs | Free tier with key |
| OpenSanctions | PEP/sanctions screening | Free non-commercial |
| WhoisXML API | WHOIS, DNS, reverse IP | 500 free credits |
| BeVigil | Mobile app OSINT | Free credits |
| Postman | Workspace leak detection | Free, no key |
| ZoomEye | Internet scanning | Paid |
| FOFA | Internet asset search | Paid |
| Snusbase | Breach/credential search | Paid |
| BBOT Subdomain Enum | 50+ passive sources | Free |
| BBOT Active Scan | Ports, HTTP, SSL, fingerprinting | Free |
| BBOT Vuln Scanner | Nuclei, badsecrets, baddns | Free |
| BBOT Cloud Recon | S3/Azure/GCP buckets | Free |
| User Scanner | Email + username checking | Free |
| MISP | Threat intel sharing | Self-hosted |
| RansomLook | Ransomware victim tracking | Free, no key |
| C2-Tracker | Live C2 server feeds | Free, no key |
| Vulners | CVE/exploit database | Free tier with key |

### Removed Modules (11)

ThreatCrowd, CRXcavator, F-Secure Riddler, Clearbit, RiskIQ, BitcoinAbuse, PunkSpider, Crobat API, Twitter, Venmo, MySpace — all dead or deprecated services.

### Fixed Modules (6)

DNSDumpster (new JSON API), DNSGrep (bufferover.run), Skymem (URL update), HackerTarget (rate limits), HaveIBeenPwned (v3 only), Keybase (deprecation notice).

## API

SpiderFoot exposes a full REST API for integration with other tools:

```bash
# Start a scan
curl -X POST http://localhost:5001/api/startscan \
  -d "scanname=test&scantarget=example.com&modulelist=sfp_dnsresolve,sfp_shodaninternetdb"

# List all scans
curl http://localhost:5001/api/scanlist

# Get scan results
curl http://localhost:5001/api/scaneventresults?id=SCAN_ID

# Export as JSON
curl http://localhost:5001/api/scanexportjsonmulti?ids=SCAN_ID

# Stop a scan
curl -X POST http://localhost:5001/api/stopscan?id=SCAN_ID
```

See [CLAUDE_TECHNICAL.md](CLAUDE_TECHNICAL.md) for the full API reference.

## Architecture

```
sf.py                          # Entry point (CLI + web server)
sflib.py                       # Core library (fetchUrl, config, helpers)
sfscan.py                      # Scan engine and module orchestration
modules/                       # 244 OSINT modules (sfp_*.py)
spiderfoot/
  app.py                       # Flask app factory
  db.py                        # SQLite database layer
  plugin.py                    # Base plugin class
  blueprints/
    api.py                     # REST API endpoints (/api/*)
    ui.py                      # HTML page routes
    fragments.py               # HTMX fragment routes (/frag/*)
  templates/                   # Jinja2 templates (pages, components, fragments)
  static/                      # CSS, JS, vendor libs
correlations/                  # YAML correlation rules
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3, Flask, SQLite |
| Frontend | Tailwind CSS (CDN), HTMX, Alpine.js |
| Templates | Jinja2 with component/fragment pattern |
| Deployment | Docker (Alpine 3.18), non-root |

## Optional Dependencies

- **bbot** — Required for the 4 `sfp_tool_bbot_*` modules. Install separately: `pip install bbot`. These modules degrade gracefully if bbot is not available.
- **nmap** — Required for `sfp_tool_nmap`. Install via system package manager.
- **whatweb** — Required for `sfp_tool_whatweb`. Install via system package manager.

## Configuration

API keys and settings are configured through the web UI at `/opts` (Settings page). Settings can also be imported/exported:

```bash
# Export settings
curl http://localhost:5001/api/optsexport > config.cfg

# Import settings
curl -X POST http://localhost:5001/api/savesettings -F "configFile=@config.cfg"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Follow the module pattern in [CLAUDE.md](CLAUDE.md) — every module needs `meta`, `opts`, `optdescs`, `setup()`, `watchedEvents()`, `producedEvents()`, `handleEvent()`
4. Use `self.sf.fetchUrl()` for all HTTP requests (never import `requests` directly)
5. Test via Docker: `docker build -t sf-test . && docker run -d -p 5001:5001 sf-test`
6. Submit a pull request

## Documentation

- [CHANGELOG.md](CHANGELOG.md) — Release history
- [CLAUDE.md](CLAUDE.md) — Project conventions and development guide
- [CLAUDE_TECHNICAL.md](CLAUDE_TECHNICAL.md) — Deep technical reference (architecture, API, DB schema)
- [correlations/README.md](correlations/README.md) — Correlation rule authoring guide

## License

MIT — see [LICENSE](LICENSE).

## Credits

Originally created by [Steve Micallef](https://github.com/smicallef/spiderfoot). This fork is maintained by [@boredchilada](https://github.com/boredchilada).
