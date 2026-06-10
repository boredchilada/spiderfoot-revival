# SpiderFoot Revival

Self-hosted OSINT automation platform forked from [SpiderFoot](https://github.com/smicallef/spiderfoot). Major overhaul — new UI, new modules, modernized stack. Current version: **5.2.0**.

## Quick Start

```bash
# Slim image — Python deps only
docker build -t spiderfoot-revival .
docker run -p 5001:5001 spiderfoot-revival
# Visit http://localhost:5001
```

For the local-tool modules (BBOT, nmap, nuclei, dnstwist, etc.) build the full image:

```bash
docker build -f Dockerfile.full -t spiderfoot-full .
docker run -p 5001:5001 -v ~/.spiderfoot:/var/lib/spiderfoot spiderfoot-full
```

## Project Structure

```
spiderfoot/
  sf.py                          # Main entry point (CLI + web server)
  sflib.py                       # Core library facade (delegates to net/*)
  sfscan.py                      # Scan engine and module orchestration
  sfcli.py                       # CLI client
  modules/                       # 244 OSINT modules (sfp_*.py)
  tailwind.config.js             # Tailwind PostCSS build config + safelist
  spiderfoot/
    app.py                       # Flask app factory, auth (bcrypt), CSRF
    db.py                        # SQLite database layer
    plugin.py                    # Base plugin class (SpiderFootPlugin)
    correlation.py               # YAML-based correlation engine
    event.py                     # SpiderFootEvent class
    target.py                    # SpiderFootTarget class
    helpers.py                   # SpiderFootHelpers utility class
    logger.py                    # SQLite log handler, queue listener
    threadpool.py                # SpiderFootThreadPool thread pool
    __version__.py               # Version (5.2.0)
    net/                         # Network utilities (extracted from sflib.py)
      http.py                    # HTTP client (fetchUrl, sessions, proxy)
      dns.py                     # DNS resolution and validation
      ssl.py                     # Certificate parsing, safe sockets
      host.py                    # IP/hostname/domain validation utilities
    services/
      event_service.py           # Event formatting, categories, badge colors
      preset_service.py          # Scan preset catalog + DB seeding
      ai_service.py              # OpenRouter chat completions client
      ai_persistence.py          # AI summary DB persistence (tbl_ai_summaries)
    blueprints/
      api.py                     # REST API endpoints (/api/*)
      ui.py                      # HTML page routes (/, /newscan, /scaninfo, /opts)
      fragments.py               # HTMX fragment routes (/frag/*)
      ai.py                      # AI summarization SSE routes (/frag/scan/*, /frag/correlation/*)
    templates/
      base.html                  # Master layout (Tailwind, HTMX, Alpine.js)
      pages/                     # Full page templates (4 pages)
      components/                # Reusable UI components (11 files)
      fragments/                 # HTMX swap fragments (17 files)
    static/
      css/custom.css             # Custom animations, scrollbars
      css/input.css              # Tailwind @layer components (custom classes)
      css/tailwind.css           # Compiled Tailwind output (built artifact)
      js/app.js                  # Alpine.js scan form component + markdown renderer
      js/theme.js                # Dark/light theme toggle
      vendor/                    # HTMX, Alpine.js
```

## Key Conventions

- **Modules**: Every module is a single `sfp_*.py` file in `modules/`. Follow the pattern in `sfp_greynoise.py` as the reference template. Every module must have `meta`, `opts`, `optdescs`, `setup()`, `watchedEvents()`, `producedEvents()`, `handleEvent()`.
- **HTTP requests**: Always use `self.sf.fetchUrl()` — never import `requests` directly.
- **Deduplication**: Use `self.results = self.tempStorage()` and check `if eventData in self.results`.
- **Error state**: Set `self.errorState = True` on fatal errors to stop the module.
- **Events**: Modules consume events via `watchedEvents()` and produce events via `self.notifyListeners(SpiderFootEvent(...))`.

## Tech Stack

- **Backend**: Python 3, Flask, SQLite
- **Frontend**: Tailwind CSS (PostCSS build), HTMX, Alpine.js, Jinja2
- **Deployment**: Docker (Alpine Linux)

## Do NOT

- Modify `sf.py`, `sflib.py`, `sfscan.py`, or `plugin.py` unless fixing a bug
- Modify `spiderfoot/net/*.py` or `spiderfoot/services/*.py` without updating the facade in `sflib.py`
- Import `requests` in modules — use `self.sf.fetchUrl()`
- Add new pages or routes — extend existing ones
- Use jQuery for new code — use Alpine.js + HTMX
- Modify `tailwind.config.js` safelist without verifying which classes are dynamically injected

## Environment (Windows)

- Dev runs on Windows 11 under Git Bash — use forward slashes in paths
- `taskkill` needs `cmd.exe //c "taskkill /PID X /F"` wrapper (Git Bash mangles `/PID`)
- **Always test via Docker** — local Python can have stale processes and missing deps
- Docker build: `docker build -t spiderfoot-revival .` then `docker run -d --name sf-test -p 5001:5001 spiderfoot-revival`
- Check logs: `docker logs sf-test 2>&1 | grep -i error`

## Gotchas

- **Alpine.js in tables**: `x-data` on a `<tr>` does NOT scope to sibling `<tr>` rows. Use `<tbody x-data="...">` to wrap row pairs (data row + detail row).
- **Alpine.js reserved words**: Don't use `open` as a variable name — conflicts with `window.open`. Use `expanded` instead.
- **Jinja2 dict key `items`**: A dict with key `items` collides with Python's `dict.items()` in Jinja2 templates. Use `entries` instead.
- **Correlation tables**: `tbl_scan_correlation_results` may not exist in older databases. Always wrap `scanCorrelationList()` calls in try/except.
- **No per-module timeout**: Modules can hang indefinitely. Only `_fetchtimeout` (5s per HTTP request) exists. A module-level timeout is a planned improvement.
- **SpiderFoot events have no inherent severity**: Don't add artificial red/amber/green severity to events. Group by category (Attack Surface, Identities, Infrastructure, Reputation, Vulnerabilities) instead.
- **Event categories**: Defined in `services/event_service.py` as `EVENT_CATEGORIES` dict — used by both summary tab and filter chips.
- **Event badge colors**: Defined in `event_badge_color()` in `services/event_service.py` — computed server-side, NOT in Jinja2 templates (Jinja2 `.startswith()` is unreliable in sandboxed Flask).
- **Tailwind safelist**: Classes used only in HTMX-swapped content (not in initial HTML) MUST be added to the `safelist` array in `tailwind.config.js`. The Tailwind CLI can't detect classes injected dynamically from Python (e.g. `event_badge_color()` return values). Rebuild with `npx tailwindcss` after changes.
- **Local tool detection**: Modules with `'tool'` in their `flags` metadata or `sfp_tool_*` prefix are shown in the Local Tools section. Set `isLocalTool` in `ui.py:_build_modules_data()`.
- **BBOT runtime args must include `--no-deps`**: BBOT's first run as a non-root user installs core deps (openssl-dev) and per-module deps via Ansible with `become: true`. The container's `spiderfoot` user has no sudo, so omitting `--no-deps` causes a silent hang on a `getpass` prompt and the SpiderFoot module sees empty stdout. `Dockerfile.full` pre-installs deps as root and copies `/root/.bbot` to `/home/spiderfoot/.bbot` so the runtime cache hit skips the install path.
- **New event types need the `eventDetails` sync**: `db.py:eventDetails` is now imported into `tbl_event_types` on every startup (not just init), so adding a new event type to that list is enough — existing DBs get migrated. The `tbl_scan_results.type` foreign key requires the row to exist before any module can emit the type.
- **Zombie scans on boot**: `start_web_server` calls `SpiderFootDb.scanInstanceReconcileZombies()` once at startup, rewriting any RUNNING/STARTING/ABORT-REQUESTED rows to ABORTED. Don't call it from `SpiderFootDb.__init__` — scan workers spawn their own DB handles and would mark their own just-started scan as a zombie.
- **API keys card builder collapses by module**: `fragments.py:_build_api_card_data` returns one card per module, with a `fields` list of every credential opt (any opt name containing `api_key`/`apikey`). Modules that need username + key (Dehashed, Censys, Twilio, IBM X-Force, etc.) render as a single card with stacked labeled inputs — never one card per opt.
