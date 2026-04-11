# SpiderFoot Revival

Self-hosted OSINT automation platform forked from [SpiderFoot](https://github.com/smicallef/spiderfoot). Major overhaul — new UI, new modules, modernized stack. Current version: **5.0.1**.

## Quick Start

```bash
docker build -t spiderfoot-revival .
docker run -p 5001:5001 spiderfoot-revival
# Visit http://localhost:5001
```

## Project Structure

```
spiderfoot/
  sf.py                          # Main entry point (CLI + web server)
  sflib.py                       # Core library (SpiderFoot class, fetchUrl, etc.)
  sfscan.py                      # Scan engine and module orchestration
  modules/                       # 244 OSINT modules (sfp_*.py)
  spiderfoot/
    app.py                       # Flask app factory
    db.py                        # SQLite database layer
    plugin.py                    # Base plugin class (SpiderFootPlugin)
    __version__.py               # Version (5.0.0)
    blueprints/
      api.py                     # REST API endpoints (/api/*)
      ui.py                      # HTML page routes (/, /newscan, /scaninfo, /opts)
      fragments.py               # HTMX fragment routes (/frag/*)
    templates/
      base.html                  # Master layout (Tailwind, HTMX, Alpine.js)
      pages/                     # Full page templates (4 pages)
      components/                # Reusable UI components (9 files)
      fragments/                 # HTMX swap fragments (13 files)
    static/
      css/custom.css             # Custom animations, scrollbars
      js/app.js                  # Alpine.js scan form component
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
- **Frontend**: Tailwind CSS (CDN in dev), HTMX, Alpine.js, Jinja2
- **Deployment**: Docker (Alpine Linux)

## Do NOT

- Modify `sf.py`, `sflib.py`, `sfscan.py`, or `plugin.py` unless fixing a bug
- Import `requests` in modules — use `self.sf.fetchUrl()`
- Add new pages or routes — extend existing ones
- Use jQuery for new code — use Alpine.js + HTMX
- Add Tailwind CDN warning suppressions — we'll move to PostCSS build later

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
- **Event categories**: Defined in `blueprints/fragments.py` as `EVENT_CATEGORIES` dict — used by both summary tab and filter chips.
