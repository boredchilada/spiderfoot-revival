# SpiderFoot Revival

Self-hosted OSINT automation platform forked from [SpiderFoot](https://github.com/smicallef/spiderfoot). This is a major overhaul — new UI, new modules, modernized stack.

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
