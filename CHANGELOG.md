# Changelog

All notable changes to the SpiderFoot Revival project.

## [5.0.3] - 2026-04-12

### Code Review — Critical & High Fixes

#### Event Pipeline
- Fixed `storeOnly` deduplication completely bypassed in threaded mode — events now carry the flag through the queue, and `waitForThreads()` enforces it by only dispatching store-only events to `__stor` modules
- Added `try/except` around `deepcopy()` in event dispatch — a single non-serializable event no longer crashes the entire scan
- Changed threadpool worker `break` to `continue` on exception — failed tasks no longer cause the worker to skip remaining module queues
- Changed `maxstorage` default from 1024 to 0 (unlimited) — stops silent truncation of SSL certificates, DNS records, and HTTP headers
- Set `storeOnly = True` when event chain depth limit (1000) is reached in `notifyListeners()` — suppresses events when dedup chain cannot be fully verified

#### Security
- Sanitized scan names in all `Content-Disposition` headers via `_safe_filename()` — prevents header injection from user-controlled scan names
- Filtered API keys, passwords, tokens, and secrets from `/api/optsexport` config download
- Blocked `tbl_config`, `ATTACH`, `PRAGMA`, and `load_extension` in `/api/query` endpoint — prevents credential extraction and SQLite abuse
- Fixed `re.sub()` in `removeUrlCreds()` where `re.IGNORECASE` was passed as positional `count` arg (value 2) instead of `flags=` keyword — case-insensitive matching and full replacement now work correctly
- Added `token=`, `secret=`, `apikey=`, `api_key=`, `access_token=` patterns to URL credential redaction
- Added `SESSION_COOKIE_HTTPONLY` and `SESSION_COOKIE_SAMESITE = 'Lax'` flags
- Added CSV formula injection protection (`_csv_safe()`) to all CSV export endpoints — prefixes `=`, `+`, `-`, `@` with single quote
- Removed `html.escape()` unescape in `clean_user_input()` that was re-introducing raw `"` and `&` after escaping
- Added redirect depth limit (10) to `fetchUrl()` refresh header handler — prevents stack overflow from malicious infinite-redirect servers
- Fixed certificate CN substring matching in `parseCert()` — `evil.example.com` no longer falsely matches a check for `example.com`

#### Authentication
- Persisted `SECRET_KEY` across server restarts via config dict — sessions and CSRF tokens no longer invalidated on every restart

#### Correlation Engine
- Added cycle detection (visited set) and depth limit (50) to `enrich_event_entities()` — prevents infinite loop on circular event graphs
- Added `None` guard in `collect_events()` — `collect_from_db()` returning `None` now returns empty list instead of crashing the correlator
- Added minimum sample size (5 buckets) to `analysis_outlier()` — prevents false-positive correlations on tiny datasets
- Fixed `field.split(".")` to `split(".", 1)` in `event_extract()`, `event_keep()`, and `event_strip()` — prevents crash on 3-level field paths in correlation headlines

#### Data Integrity
- Increased event ID entropy from `randint(0, 99999999)` (~26.5 bits) to `getrandbits(64)` — eliminates birthday collision risk that could kill the storage module

#### Code Quality
- Added `DEVICE_TYPE`, `RAW_RIR_DATA`, `TCP_PORT_OPEN_BANNER`, `CO_HOSTED_SITE_DOMAIN`, `AFFILIATE_INTERNET_NAME`, `AFFILIATE_DOMAIN_NAME` to `EVENT_CATEGORIES` — these no longer fall into "Other" bucket in UI summary
- Moved `import time` to module level in `fragments.py` — was being re-imported inside loops on every HTTP request
- Standardized log timestamp handling — always divide by 1000 (removed conditional check)

---

## [5.0.2] - 2026-04-11

### Security Hardening

#### Authentication & Access Control
- Added HTTP Basic Auth via `before_request` hook — all endpoints protected by default when passwd file is configured (`~/.spiderfoot/passwd`)
- Static files and `/api/ping` health check exempt from auth
- Timing-safe password comparison via `hmac.compare_digest` to prevent enumeration
- Loud startup warning when binding to non-localhost without authentication

#### CSRF Protection
- Added HMAC-signed CSRF tokens via Flask sessions, enforced on all POST requests
- CSRF token auto-injected into all HTMX requests via `htmx:configRequest` listener
- CSRF token included in scan submission and settings save fetch calls
- API clients using Basic Auth bypass CSRF (not vulnerable to browser-based attacks)
- Removed legacy `SF_TOKEN` random integer mechanism

#### Network Attack Surface
- Removed unrestricted CORS (`flask-cors` dependency deleted) — no cross-origin access needed
- All state-modifying endpoints now POST-only (scandelete, stopscan, startscan, vacuum, etc.)
- Hardened `/query` endpoint: read-only SQLite connection, semicolons rejected, error details no longer leaked to client
- Added scan creation rate limiting (configurable max concurrent scans, default 10)
- Hardcoded `debug=False` in production — Flask debugger no longer toggleable from config
- Switched CLI (`sfcli.py`) from HTTP Digest Auth to Basic Auth

#### Input Sanitization & XSS
- Fixed SQL injection in `scanElementSourcesDirect` and `scanElementChildrenDirect` — parameterized IN clauses replace string interpolation
- Archived legacy CherryPy UI files (sfwebui.py, .tmpl templates, legacy JS) — eliminates 4 critical stored XSS vectors, 1 infinite loop, and broken template literals
- URL-encoded `scan.target` in re-scan link href to prevent parameter injection
- API key values masked with `********` in HTML source; sentinel skipped on save
- Removed global `ssl._create_default_https_context` override — SSL verification no longer disabled process-wide

### Bug Fixes — Correctness & Data Integrity
- Fixed `getAddresses()` overwriting IPv4 results with IPv6 (`extend` instead of reassign)
- Fixed `scanElementChildrenAll` only following last child branch (`nextIds` reset moved outside loop)
- Fixed `correlationResultCreate` non-atomic insert — correlation result and event hashes now commit in a single transaction
- Fixed correlation meta cleaning bug — `else` branch incorrectly referenced `rule[k]` instead of `rule['meta'][k]`
- Fixed `build_correlation_title` crash when `event_extract` fails — uninitialized variable now handled with `continue`
- Fixed `logBatch` race condition — batch swap now protected by `threading.Lock`
- Fixed missing path separator in `loadCorrelationRulesRaw` — uses `os.path.join`
- Fixed unreachable `return False` in `vacuumDB`
- Fixed stale loop variable in `scanElementSourcesAll` — guarded with `if nextIds`
- Moved mutable class-level `_listenerModules` and `opts` to `__init__` in plugin base class — prevents cross-instance state leakage
- Added depth limit (1000) to event chain traversal in `notifyListeners` — prevents infinite loops from circular references
- Replaced MD5-based correlation IDs with `uuid.uuid4().hex`

### Tech Debt & Cleanup
- Updated default user-agent from Firefox 62 (2018) to Firefox 128
- Fixed wrong type hints in threadpool (`str` → `queue.Queue`, `None` → `Generator`)
- Replaced broad `suppress(Exception)` with specific exceptions in threadpool
- Cached `countryCodes()` dict as class variable — no longer rebuilt on every call
- Refactored `extractLinksFromHtml` to parse HTML once instead of 7 times
- Conditional scan table polling interval (5s when scans running, 30s when idle)
- Converted `parsedTargets()` to getter in Alpine.js scan form for render-cycle caching
- Safe `int()` parsing on page parameter with fallback to 1

### UX Overhaul

#### Dashboard
- Renamed page title from "Scans" to "Dashboard" to match nav
- Renamed "Correlations" stat card to "Findings" with "from X scans" subtitle
- "94 need API keys" is now a clickable link to Settings
- Improved empty state with guidance text and "Start your first scan" CTA

#### New Scan Page
- Added **module search bar** — instant filtering across all 241 modules by name, description, category, or key
- Added **Local Tools section** — dedicated dashed-border accordion grouping 17 tool modules (bbot, nmap, whatweb, etc.) by sub-category with synced toggles
- Rewrote scan type descriptions for non-security users ("Discover public info about a target" instead of "Map the attack surface")
- "KEY NEEDED" badges now link to Settings with arrow indicator
- Added intro text explaining what modules are and how API keys work
- Module descriptions show full text on hover via title attribute

#### Scan Results
- Replaced duplicate "Sources" stat card with "Duration" card
- Added "Soon" badge on Graph tab to set expectations
- Graph placeholder now explains GEXF export for use in Gephi/yEd
- Standardized severity labels: HIGH→Critical, MEDIUM→Warning, LOW→Low, INFO→Info (consistent across Summary and Correlations tabs)
- Improved empty state explanations for findings, events, and correlations

#### Data Tab (Redesigned)
- Replaced dense table layout with clean flex-based rows
- Color-coded type badges by event category: cyan (network/DNS), emerald (infrastructure/SSL), violet (identity), red (malicious), orange (vulnerabilities), amber (threat intel), slate (raw data)
- Badge colors computed server-side for cross-browser reliability
- Smart data preview: Web Content events show "HTML document · X chars" instead of raw HTML entities
- Long data truncated at 120 chars in preview, full content in expandable detail panel
- Detail panel has metadata header (type code, module, timestamp, confidence), Copy button, and scrollable container for large payloads
- "All" chip added to category filters for easy reset
- Copy-to-clipboard button for event data

#### Settings
- **API Keys**: Grouped 94 keys by module category with collapsible headers and configured/total counters; auto-expands groups with configured keys; intro text about free tiers; search bar; service website links on each card
- **General**: Improved helper text with practical guidance (thread performance trade-offs, DNS server examples, user agent purpose, timeout advice)
- **Proxy/TOR**: Contextual help text changes based on proxy type; fields visually disabled when "None" selected; improved descriptions
- **Appearance**: Added "Auto" theme option that follows OS preference via prefers-color-scheme

#### Global
- Sidebar expand hint chevron (visible when collapsed, hidden when expanded)
- Standardized save feedback to 4-second auto-hide across all settings sections
- Replaced browser `alert()` in scan submission with inline toast notifications
- Added loading spinner on Launch Scan button during submission
- Added Tailwind CDN safelist for HTMX-swapped classes (Firefox compatibility)
- Theme system updated to support dark/light/auto with OS preference listener

---

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
