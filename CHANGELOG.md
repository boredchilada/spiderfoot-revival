# Changelog

All notable changes to the SpiderFoot Revival project.

## [5.0.1] - 2026-04-10

### Bug Fixes — Critical
- Fixed `Popen(timeout=)` TypeError crash in `sfp_userscanner` and `sfp_tool_whatweb` — timeout arg moved to `.communicate()`
- Fixed wrong event type constants in `sfp_tool_bbot_cloud` and `sfp_bevigil` — `CLOUD_STORAGE_OPEN` → `CLOUD_STORAGE_BUCKET_OPEN`, `CODE_REPOSITORY` → `PUBLIC_CODE_REPO`
- Fixed `sfp_postman` using non-existent `CODE_REPOSITORY` event type → `PUBLIC_CODE_REPO`
- Fixed scan delete button 405 error — changed `hx-delete` to `hx-post` (route only accepts GET/POST)
- Fixed scan delete DOM breakage — `hx-swap="delete"` instead of injecting raw JSON into table
- Fixed MISP module mapping EMAILADDR → `MALICIOUS_INTERNET_NAME` (now correctly → `MALICIOUS_EMAILADDR`)
- Fixed `sfp_opensanctions` emitting semantically wrong `MALICIOUS_AFFILIATE_INTERNET_NAME` for sanctions/PEP matches
- Fixed null reference crashes in `sfp_haveibeenpwned` and `sfp_skymem` when `fetchUrl()` returns None
- Fixed settings save broken on first use — CSRF token was `None` until `/api/optsraw` was called
- Fixed `del pc['ROOT']` KeyError crash in `/api/scanelementtypediscovery` when scan has no events
- Fixed scan start/rerun infinite loop — added 30s timeout so Flask workers don't hang if subprocess fails

### Bug Fixes — Data Correctness
- Fixed `scanInstanceDelete` not cleaning correlation tables — orphaned rows in `tbl_scan_correlation_results`
- Fixed log timestamps displayed as raw milliseconds in Log tab fragments
- Fixed `scanLogs` reverse parameter logic (was inverted — `reverse=True` returned oldest instead of newest)
- Fixed JSON and GEXF export buttons calling wrong API endpoints (now use `/scanexportjsonmulti` and `/scanviz?gexf=1`)
- Fixed correlation export filename typo `.xlxs` → `.xlsx`
- Wrapped `scanCorrelationSummary` calls in `/api/scanlist` and `/api/scanstatus` with try/except for older databases
- Fixed DB schema FK typo `tbl_scan_instances` → `tbl_scan_instance`

### Bug Fixes — UX
- Added `[x-cloak]` CSS rule — expandable rows no longer flash visible before Alpine.js initializes
- Fixed stop button replacing its own text with JSON response — added `hx-swap="none"`
- Fixed `sfp_c2tracker` not setting `errorState` on fetch failure (caused repeated retry flood)
- Fixed `sfp_dnsgrep` missing `errorState` class var and guard in `handleEvent()`
- Fixed `sfp_postman` not setting `errorState` on 429 rate limit (caused retry storm)
- Fixed `sfp_tool_bbot_vuln` and `sfp_tool_bbot_cloud` emitting `RAW_RIR_DATA` for every BBOT output line (now only for relevant events)
- Fixed `sfp_fofa` emitting duplicate `WEBSERVER_BANNER` events

### Cleanup
- Removed unused `SpiderFootHelpers` import from `sfp_tool_bbot_scan`
- Moved inline `import json`/`import time` to module level in `sfp_dnsdumpster`
- Removed dead `re` and `BeautifulSoup` imports from `sfp_dnsdumpster` (left over from old HTML scraping version)
- Removed false `COMPANY_NAME`/`HUMAN_NAME` declarations from `sfp_opensanctions` producedEvents (were never emitted)
- Removed duplicate scrollbar CSS rules and 5 unused CSS classes from `custom.css`
- Moved `@import` font rules to top of `custom.css` (CSS spec requirement)

### Infrastructure
- Added `user-scanner` to `requirements.txt`
- Relaxed `pyOpenSSL`, `cryptography`, and `networkx` version bounds for compatibility
- Bumped Dockerfile Alpine from 3.12/3.13 to 3.18 (Python 3.11 support, needed for modern dependencies)
- `bbot` documented as optional dependency (too heavy for default install, modules degrade gracefully)

## [5.0.0] - 2026-04-08

### Phase 1: UI/UX Overhaul (completed prior)
- Migrated from CherryPy to Flask
- Rebuilt frontend with Tailwind CSS, HTMX, Alpine.js
- Dark SOC-themed UI with collapsible sidebar
- Component-based Jinja2 templates with HTMX fragment loading
- New scan creation page with multi-target support and module category toggles

### Phase 2: Module Audit & New Services

#### Removed (11 dead/deprecated modules)
- `sfp_threatcrowd` — ThreatCrowd shut down
- `sfp_crxcavator` — CRXcavator shut down
- `sfp_fsecure_riddler` — F-Secure Riddler EOL
- `sfp_clearbit` — Clearbit acquired by HubSpot, API dead
- `sfp_riskiq` — RiskIQ acquired by Microsoft, old API dead
- `sfp_bitcoinabuse` — Merged into ChainAbuse
- `sfp_punkspider` — QOMPLX collapsed
- `sfp_crobat_api` — omnisint.io dead
- `sfp_twitter` — Twitter/X free API removed
- `sfp_venmo` — Venmo API closed to new developers
- `sfp_myspace` — No useful API remaining

#### Fixed (6 modules with changed APIs)
- `sfp_dnsdumpster` — Rewrote from CSRF scraping to new JSON API with API key
- `sfp_dnsgrep` — Updated to tls.bufferover.run with x-api-key header
- `sfp_skymem` — Updated URLs from skymem.info to skymem.com
- `sfp_hackertarget` — Updated model to FREE_NOAUTH_LIMITED, documented rate limits
- `sfp_haveibeenpwned` — Removed dead v2 fallback, v3 API only with required key
- `sfp_keybase` — Added deprecation notice (Zoom acquisition, maintenance mode)

#### Added — New OSINT Service Modules (13)
- `sfp_shodaninternetdb` — Shodan InternetDB (free, no key, ports/CVEs/hostnames)
- `sfp_leakcheck` — LeakCheck breach database (free public API + pro)
- `sfp_hudsonrock` — Hudson Rock Cavalier infostealer intelligence (free)
- `sfp_criminalip` — Criminal IP threat intel (free tier with key)
- `sfp_netlas` — Netlas.io attack surface search (free tier with key)
- `sfp_validin` — Validin DNS history and CT logs (free tier with key)
- `sfp_opensanctions` — OpenSanctions PEP/sanctions screening (free non-commercial)
- `sfp_whoisxmlapi` — WhoisXML API WHOIS/DNS/reverse IP (500 free credits)
- `sfp_bevigil` — BeVigil mobile app OSINT (free credits)
- `sfp_postman` — Postman public workspace leak detection (free, no key)
- `sfp_zoomeye` — ZoomEye internet scanning (paid)
- `sfp_fofa` — FOFA internet asset search (paid)
- `sfp_snusbase` — Snusbase breach/credential search (paid)

#### Added — BBOT Integration (4 tool wrappers)
- `sfp_tool_bbot_enum` — BBOT subdomain enumeration (50+ passive sources)
- `sfp_tool_bbot_scan` — BBOT active scanning (ports, HTTP, SSL, fingerprinting)
- `sfp_tool_bbot_vuln` — BBOT vulnerability detection (nuclei, badsecrets, baddns)
- `sfp_tool_bbot_cloud` — BBOT cloud recon (S3/Azure/GCP buckets, Docker Hub, Postman)

#### Added — Threat Intelligence Modules (5)
- `sfp_userscanner` — Email registration + username scanning across 195+ platforms
- `sfp_misp` — MISP Threat Intelligence Sharing Platform integration
- `sfp_ransomlook` — RansomLook ransomware victim tracking (free, no key)
- `sfp_c2tracker` — C2-Tracker live C2 server IP feed (free, no key)
- `sfp_vulners` — Vulners CVE/exploit database (free tier with key)

### Phase 2: UX Polish

#### Dashboard
- Stats cards: 4 cards (Active Scans, Completed, Correlations, Modules) with contextual second lines
- Scan rows: inline event type breakdown (hosts, IPs, emails, ports) + progress bars for running scans
- Removed flat column layout in favor of single-column rich rows

#### Scan Results
- Summary tab: events grouped by category (Attack Surface, Identities & Exposure, Infrastructure, Reputation, Vulnerabilities) instead of flat number grid
- Stat cards: renamed to Events/Correlations/Modules/Sources with context lines (unique count, duration, risk breakdown)
- Data tab: category filter chips with counts, expandable rows for full event detail, pagination (50 per page replacing 500-row hard cap)

#### Bug Fixes
- Fixed Alpine.js `open` / `window.open` conflict (renamed to `expanded`)
- Fixed Alpine.js scoping in table rows (tbody-per-row pattern for sibling access)
- Fixed correlation query error on databases without correlation tables

### Module Count
- Previous: 233 modules
- Removed: 11 dead modules
- Added: 22 new modules
- **Current: 244 modules**
