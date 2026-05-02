# SpiderFoot Revival — Technical Reference

## Architecture

### Event System
SpiderFoot's core is an event-driven pipeline:
1. User provides a target (domain, IP, email, etc.)
2. The scan engine creates a root event (`ROOT`)
3. Modules that watch for ROOT produce new events (e.g., `DOMAIN_NAME`)
4. Other modules consume those events and produce more (e.g., `INTERNET_NAME`, `IP_ADDRESS`)
5. This cascades until no module produces new events

Events are typed strings. Key event types:
- `INTERNET_NAME`, `DOMAIN_NAME`, `IP_ADDRESS` — core discovery
- `TCP_PORT_OPEN`, `UDP_PORT_OPEN` — port scanning
- `EMAILADDR`, `EMAILADDR_COMPROMISED`, `USERNAME` — identity
- `VULNERABILITY_CVE_CRITICAL/HIGH/MEDIUM/LOW` — CVEs
- `MALICIOUS_IPADDR`, `BLACKLISTED_IPADDR` — reputation
- `LEAKSITE_CONTENT`, `DARKNET_MENTION_CONTENT` — breach/darknet
- `RAW_RIR_DATA` — raw data for archival

### Module Types
1. **API modules** (e.g., `sfp_shodan.py`): Query external REST APIs
2. **Tool wrappers** (e.g., `sfp_tool_nmap.py`): Shell out to CLI tools, parse output
3. **Internal modules** (e.g., `sfp_dnsresolve.py`): Local analysis, no external calls
4. **Feed modules** (e.g., `sfp_c2tracker.py`): Download and cross-reference threat feeds

### Database
SQLite via `spiderfoot/db.py`. Key tables:
- `tbl_scan_instance` — scan metadata (id, target, status, timestamps)
- `tbl_scan_results` — all events (type, data, module, hash, parent_hash)
- `tbl_scan_config` — per-scan module configuration
- `tbl_scan_correlation_results` — correlation rule matches
- `tbl_config` — global settings (API keys, proxy, etc.)

### Flask App
- `app.py`: Factory pattern, registers 3 blueprints
- `blueprints/api.py`: REST API (scan lifecycle, data export, config)
- `blueprints/ui.py`: HTML pages (dashboard, newscan, scaninfo, settings)
- `blueprints/fragments.py`: HTMX fragments (tab content, table rows, settings sections)

All API endpoints are dual-registered at `/api/*` and `/*` for backwards compatibility.

### Frontend
- **Tailwind CSS**: CDN in development, `tailwind.config.js` defines `sf.*` color tokens
- **HTMX**: Fragment-driven updates (scan table polling, tab switching, search/filter)
- **Alpine.js**: Reactive components (scan form, theme toggle, expandable rows)
- **No build step**: Everything runs from CDN/static files in development

### HTMX Patterns
- Scan table polls every 5s: `hx-trigger="every 5s"`
- Tab switching: `hx-get="/frag/results-tab?id=X&tab=Y"` → `hx-target="#tab-content"`
- Search/filter: `hx-trigger="keyup changed delay:300ms"` with `hx-include` for multi-field
- Pagination: `hx-get="/frag/events?id=X&page=N"` → `hx-target="#event-rows"`

### Event Categories (for UI grouping)
Defined in `services/event_service.py` as `EVENT_CATEGORIES`:
- **Attack Surface**: INTERNET_NAME, IP_ADDRESS, TCP_PORT_OPEN, DOMAIN_NAME
- **Identities & Exposure**: EMAILADDR, USERNAME, SOCIAL_MEDIA, LEAKSITE_CONTENT
- **Infrastructure**: WEBSERVER_TECHNOLOGY, SSL_CERTIFICATE, BGP_AS_MEMBER, GEOINFO
- **Reputation**: MALICIOUS_IPADDR, BLACKLISTED_*, flagged affiliates
- **Vulnerabilities**: VULNERABILITY_CVE_*, VULNERABILITY_GENERAL

## Module Anatomy

```python
class sfp_example(SpiderFootPlugin):
    meta = {
        "name": "Example Service",
        "summary": "What it does in one line.",
        "flags": ["apikey"],                    # or [] for no-auth
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Search Engines"],
        "dataSource": {
            "website": "https://example.com/",
            "model": "FREE_AUTH_LIMITED",        # or FREE_NOAUTH_UNLIMITED, COMMERCIAL_ONLY
            "references": ["https://docs.example.com/"],
            "apiKeyInstructions": ["Visit...", "Sign up...", "Copy key..."],
            "description": "...",
        },
    }

    opts = {"api_key": "", "request_delay": 1.0}
    optdescs = {"api_key": "Example API key.", "request_delay": "Delay between requests."}

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS", "DOMAIN_NAME"]

    def producedEvents(self):
        return ["INTERNET_NAME", "RAW_RIR_DATA"]

    def handleEvent(self, event):
        if self.errorState:
            return
        if event.data in self.results:
            return
        self.results[event.data] = True

        # Query API using self.sf.fetchUrl()
        res = self.sf.fetchUrl(url, headers=headers, timeout=self.opts["_fetchtimeout"])
        # Parse response, emit events
        e = SpiderFootEvent("INTERNET_NAME", hostname, self.__name__, event)
        self.notifyListeners(e)
```

## API Endpoints

### Scan Lifecycle
| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/startscan` | Start scan (params: scanname, scantarget, modulelist) |
| POST | `/api/stopscan?id=X` | Stop running scan |
| POST | `/api/scandelete?id=X` | Delete scan and data |
| GET | `/api/scanlist` | List all scans |
| GET | `/api/scanstatus?id=X` | Scan status + risk matrix |

### Data Retrieval
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/scaneventresults?id=X` | All events for a scan |
| GET | `/api/scansummary?id=X&by=type` | Summary grouped by type or module |
| GET | `/api/search?id=X&value=Y` | Search events (supports regex) |
| GET | `/api/scanexportjsonmulti?ids=X,Y` | Export as JSON |

### Config
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/optsexport` | Export config as CFG file |
| POST | `/api/savesettings` | Import config (JSON or CFG file) |
| GET | `/api/modules` | List all available modules |

## Current Module Count: 245

### By API Model
- FREE_NOAUTH_UNLIMITED: ~35 modules
- FREE_NOAUTH_LIMITED: ~11 modules
- FREE_AUTH_LIMITED: ~55 modules
- FREE_AUTH_UNLIMITED: ~15 modules
- COMMERCIAL_ONLY: ~10 modules
- Internal (no API): ~40 modules
- Tool wrappers: 17 modules

### New in v5.0.0 (22 modules)
Shodan InternetDB, LeakCheck, Hudson Rock, Criminal IP, Netlas.io, Validin, OpenSanctions, WhoisXML API, BeVigil, Postman, ZoomEye, FOFA, Snusbase, BBOT (4 wrappers), User Scanner, MISP, RansomLook, C2-Tracker, Vulners

### New in v5.1.0 (1 module)
Ransomware.live — leak-site victim lookup via the free v2 API. Adds the `RANSOMWARE_VICTIM` event type. Watches `DOMAIN_NAME` / `COMPANY_NAME` by default (configurable allowlist), 24h response cache, 65s inter-call throttle to respect the free 1 req/min limit.

## Scan Lifecycle

### Status Flow
```
STARTING → RUNNING → FINISHED
                   → ABORT-REQUESTED → ABORTED
                   → ERROR-FAILED
```

### How Scans Run
1. `POST /api/startscan` creates a scan instance in SQLite, spawns a `Process` (not thread)
2. The scan process loads selected modules, creates event queues
3. Root event is injected, modules consume/produce events via `handleEvent()`
4. Each module has its own `incomingEventQueue` and `outgoingEventQueue`
5. Modules call `self.checkForStop()` to poll for abort requests
6. When all queues are empty, scan transitions to `FINISHED`

### Known Limitation: No Per-Module Timeout
- `_fetchtimeout` (default 5s) only applies to individual HTTP requests via `fetchUrl()`
- There is NO timeout on module execution itself — a module iterating a /16 netblock or running BBOT can run for hours
- Workaround: manually `POST /api/stopscan?id=X` to set `ABORT-REQUESTED`

### Zombie Scan Reconciliation
- If the scan process dies abnormally (Docker restart, OOM, crash) the DB row stays `RUNNING` / `STARTING` / `ABORT-REQUESTED` indefinitely
- `start_web_server` calls `SpiderFootDb.scanInstanceReconcileZombies()` once before `create_app()`, rewriting all such rows to `ABORTED` with the current timestamp on `ended`
- The reconciler is intentionally NOT in `SpiderFootDb.__init__` — scan workers spawn their own DB handle and would mark their own just-started scan as a zombie

### Config Import/Export
- `GET /api/optsexport` → text/plain CFG file, format: `modulename:optionname=value` per line
- `POST /api/savesettings` → accepts JSON (`allopts` param) or CFG file upload (`configFile` param)
- Requires CSRF token from `GET /api/optsraw` (returned in response)
- `configSerialize()` and `configUnserialize()` in `sflib.py` handle the conversion
- Both methods iterate `__modules__` dynamically — new modules are auto-included

## Template Patterns

### Alpine.js in Tables
Tables don't allow wrapper elements between `<tr>` rows. For expandable row pairs:
```html
<!-- WRONG: x-data on <tr> doesn't scope to sibling <tr> -->
<tr x-data="{ expanded: false }">...</tr>
<tr x-show="expanded">...</tr>  <!-- Can't see 'expanded'! -->

<!-- RIGHT: wrap both rows in <tbody> -->
<tbody x-data="{ expanded: false }">
  <tr @click="expanded = !expanded">...</tr>
  <tr x-show="expanded" x-cloak>...</tr>
</tbody>
```

### HTMX Fragment Swap Target
The data tab uses a `<table id="event-rows">` as the HTMX swap target. The fragment response contains `<tbody>` elements (one per expandable row pair). HTMX's default `innerHTML` swap replaces the table's children correctly.

### Jinja2 Pitfalls
- Dict key `items` → collides with `dict.items()`. Use `entries` instead.
- `{{ "{:,}".format(number) }}` for comma-formatted numbers
- `{{ [a, b] | min }}` for inline min in templates

## Database Schema (Key Queries)

```sql
-- Scan list with event counts
SELECT s.guid, s.name, s.seed_target, s.created, s.started, s.ended,
       s.status, COUNT(r.type) FROM tbl_scan_instance s
LEFT JOIN tbl_scan_results r ON s.guid = r.scan_instance_id
GROUP BY s.guid ORDER BY s.started DESC

-- Event summary by type
SELECT r.type, e.event_descr, MAX(r.generated) AS last_in,
       COUNT(r.type) AS total, COUNT(DISTINCT r.data) AS utotal
FROM tbl_scan_results r, tbl_event_types e
WHERE r.scan_instance_id = ? AND r.type = e.event
GROUP BY r.type ORDER BY e.event_descr

-- Events for a scan (used by data tab)
SELECT r.generated, r.data, r.source_data, r.module, r.type,
       r.confidence, r.visibility, r.risk, r.hash, r.source_event_hash,
       e.event_descr, e.event_type, r.scan_instance_id, r.false_positive
FROM tbl_scan_results r, tbl_event_types e
WHERE r.scan_instance_id = ? AND r.type = e.event
ORDER BY r.generated DESC
```

## Docker

Two images:

```bash
# Slim — Python deps only (Alpine 3.18, multi-stage build, non-root)
docker build -t spiderfoot-revival .
docker run -p 5001:5001 -v ~/.spiderfoot:/var/lib/spiderfoot spiderfoot-revival

# Full — Python + every local-tool CLI binary the modules wrap
docker build -f Dockerfile.full -t spiderfoot-full .
docker run -p 5001:5001 -v ~/.spiderfoot:/var/lib/spiderfoot spiderfoot-full
```

The full image is `python:3.11`-based (lxml<5 has no wheels on 3.13) and ships nmap, nuclei, whatweb, dnstwist, cmseek, wafw00f, onesixtyone, nbtscan, retire, testssl.sh, snallygaster, trufflehog, and BBOT with all module deps pre-installed.

For BBOT active port scanning (masscan SYN scans) add `--cap-add=NET_RAW`; without it BBOT falls back to TCP-connect.

### Optional Dependencies
- **bbot**: Required for `sfp_tool_bbot_*` modules. Pre-installed in `Dockerfile.full`. For local dev: `pip install bbot && bbot --install-all-deps -y`. Modules pass `--no-deps` at runtime; if you skip the install step BBOT will hang on a sudo prompt and silently emit nothing.
- **user-scanner**: Included in `requirements.txt`. Used by `sfp_userscanner` for email registration + username checking.

### Event Type Reference (common mistakes)
- Cloud buckets: `CLOUD_STORAGE_BUCKET` (exists) / `CLOUD_STORAGE_BUCKET_OPEN` (open). NOT `CLOUD_STORAGE_OPEN`.
- Code repos: `PUBLIC_CODE_REPO`. NOT `CODE_REPOSITORY`.
- Malicious emails: `MALICIOUS_EMAILADDR`. NOT `MALICIOUS_INTERNET_NAME` for email indicators.

### Testing Workflow
```bash
docker stop sf-test 2>/dev/null; docker rm sf-test 2>/dev/null
docker build -t spiderfoot-revival .
docker run -d --name sf-test -p 5001:5001 spiderfoot-revival
sleep 5
curl -s -o /dev/null -w "%{http_code}" http://localhost:5001/       # Dashboard
curl -s -o /dev/null -w "%{http_code}" http://localhost:5001/newscan # New scan
docker logs sf-test 2>&1 | grep -i error                            # Check errors
```
