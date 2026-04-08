import html
import logging
import os

from flask import Blueprint, current_app, render_template, request

from spiderfoot import SpiderFootDb

frag_bp = Blueprint('frag', __name__)

log = logging.getLogger(f"spiderfoot.{__name__}")


def _get_db():
    """Create a SpiderFootDb handle using the current app config."""
    return SpiderFootDb(current_app.config['SF_CONFIG'])


def _load_scans():
    """Return a list of scan dicts for rendering."""
    try:
        dbh = _get_db()
        rows = dbh.scanInstanceList()
    except Exception as e:
        log.warning("Fragment: could not load scan list: %s", e)
        return []

    scans = []
    for row in rows:
        scans.append({
            'id': row[0],
            'name': row[1],
            'target': row[2],
            'created': row[3],
            'started': row[4],
            'ended': row[5],
            'status': row[6],
            'num_results': int(row[7] or 0),
        })
    return scans


@frag_bp.route('/scan-table')
def scan_table():
    """Return the <tbody> rows for the scan table (HTMX swap target)."""
    scans = _load_scans()
    return render_template('fragments/scan_tbody.html', scans=scans)


@frag_bp.route('/results-tab')
def results_tab():
    """Return HTML for a scan results tab (HTMX swap target)."""
    scan_id = request.args.get('id', '')
    tab = request.args.get('tab', 'summary')

    if not scan_id:
        return '<p class="text-sm text-slate-400 p-8 text-center">No scan selected.</p>'

    dbh = _get_db()

    if tab == 'summary':
        # Event summary by type: (type, event_descr, last_in, total, utotal)
        try:
            event_summary = dbh.scanResultSummary(scan_id, 'type')
        except Exception:
            event_summary = []

        # Build findings from correlations
        try:
            correlations = dbh.scanCorrelationList(scan_id)
        except Exception:
            correlations = []

        findings = []
        for c in correlations:
            findings.append({
                'id': c[0],
                'title': c[1],
                'rule_id': c[2],
                'risk': c[3] or 'INFO',
                'rule_name': c[4],
                'description': c[5] or '',
                'event_count': c[7] if len(c) > 7 else 0,
            })

        return render_template(
            'fragments/results_summary.html',
            findings=findings,
            event_summary=event_summary,
        )

    elif tab == 'data':
        try:
            raw_events = dbh.scanResultEvent(scan_id, 'ALL')[:500]
        except Exception:
            raw_events = []

        # Build event dicts for the template
        # Columns: generated, data, source_data, module, type, confidence,
        #          visibility, risk, hash, source_event_hash, event_descr,
        #          event_type, scan_instance_id, fp, parent_fp
        events = []
        for e in raw_events:
            events.append({
                'type': e[10] or e[4],  # event_descr or type code
                'type_code': e[4],
                'data': html.escape(str(e[1] or '')),
                'module': e[3],
                'confidence': e[5],
                'risk': e[7],
            })

        # Get event types for the filter dropdown
        try:
            event_types = dbh.scanResultSummary(scan_id, 'type')
        except Exception:
            event_types = []

        return render_template(
            'components/event_table.html',
            events=events,
            event_types=event_types,
            scan_id=scan_id,
        )

    elif tab == 'graph':
        return render_template(
            'fragments/results_graph.html',
            scan_id=scan_id,
        )

    elif tab == 'timeline':
        # History: (hourmin, type, count)
        try:
            history = dbh.scanResultHistory(scan_id)
        except Exception:
            history = []

        return render_template(
            'fragments/results_timeline.html',
            history=history,
        )

    elif tab == 'correlations':
        try:
            correlations = dbh.scanCorrelationList(scan_id)
        except Exception:
            correlations = []

        return render_template(
            'fragments/results_correlations.html',
            correlations=correlations,
        )

    return '<p class="text-sm text-slate-400 p-8 text-center">Unknown tab.</p>'


@frag_bp.route('/events')
def events_fragment():
    """Return filtered event table rows (HTMX swap target for search/filter)."""
    scan_id = request.args.get('id', '')
    type_filter = request.args.get('type_filter', 'ALL')
    query = request.args.get('q', '').strip().lower()

    if not scan_id:
        return ''

    dbh = _get_db()

    try:
        raw_events = dbh.scanResultEvent(scan_id, type_filter or 'ALL')[:500]
    except Exception:
        raw_events = []

    events = []
    for e in raw_events:
        data_str = str(e[1] or '')
        # Apply search filter
        if query and query not in data_str.lower() and query not in (e[3] or '').lower() and query not in (e[10] or e[4] or '').lower():
            continue
        events.append({
            'type': e[10] or e[4],
            'type_code': e[4],
            'data': html.escape(data_str),
            'module': e[3],
            'confidence': e[5],
            'risk': e[7],
        })

    return render_template(
        'fragments/event_rows.html',
        events=events,
    )


# ---------------------------------------------------------------------------
# Settings sections
# ---------------------------------------------------------------------------

def _human_size(num_bytes: int) -> str:
    """Convert a byte count to a human-readable string."""
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"


def _build_api_card_data(sf_config: dict) -> list:
    """Scan all modules for API key options and return sorted card list."""
    modules_cfg = sf_config.get('__modules__', {})
    cards = []

    for mod_name, mod_cfg in modules_cfg.items():
        if mod_name.startswith('sfp__stor_'):
            continue

        meta = mod_cfg.get('meta', {})
        service_name = meta.get('name', mod_name)
        opts = mod_cfg.get('opts', {})

        for opt_key, opt_val in opts.items():
            key_lower = opt_key.lower()
            if 'api_key' in key_lower or 'apikey' in key_lower:
                # Try to get the stored/live value
                value = str(opt_val) if opt_val is not None else ''
                configured = bool(value and value.strip())
                cards.append({
                    'mod_name': mod_name,
                    'service_name': service_name,
                    'opt_key': opt_key,
                    'value': value,
                    'configured': configured,
                })

    # Sort: configured first, then alphabetically by service name
    cards.sort(key=lambda c: (0 if c['configured'] else 1, c['service_name'].lower()))
    return cards


@frag_bp.route('/settings-section')
def settings_section():
    """Return a settings section fragment (HTMX swap target)."""
    section = request.args.get('section', 'general')
    sf_config = current_app.config.get('SF_CONFIG', {})

    # Load saved config from DB and merge
    try:
        dbh = _get_db()
        saved_config = dbh.configGet()
    except Exception as e:
        log.warning("settings_section: could not load config: %s", e)
        saved_config = {}

    config = dict(sf_config)
    config.update(saved_config)

    if section == 'general':
        return render_template('fragments/settings_general.html', config=config)

    elif section == 'apikeys':
        # Merge saved per-module opts into the module defaults
        modules_cfg = sf_config.get('__modules__', {})
        for mod_name, mod_cfg in modules_cfg.items():
            opts = mod_cfg.get('opts', {})
            for opt_key in list(opts.keys()):
                db_key = f"{mod_name}:{opt_key}"
                if db_key in saved_config:
                    opts[opt_key] = saved_config[db_key]

        cards = _build_api_card_data(sf_config)
        return render_template('fragments/settings_apikeys.html', cards=cards)

    elif section == 'proxy':
        return render_template('fragments/settings_proxy.html', config=config)

    elif section == 'database':
        db_path = sf_config.get('__database') or os.path.expanduser('~/.spiderfoot/spiderfoot.db')
        try:
            db_size = _human_size(os.path.getsize(db_path))
        except OSError:
            db_size = 'Unknown'
        return render_template(
            'fragments/settings_database.html',
            db_path=db_path,
            db_size=db_size,
        )

    elif section == 'appearance':
        return render_template('fragments/settings_appearance.html')

    return '<p class="text-sm text-slate-400 p-6">Unknown section.</p>'
