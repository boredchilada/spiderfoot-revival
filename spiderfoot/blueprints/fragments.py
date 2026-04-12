import logging
import os
import time
from collections import OrderedDict

from flask import Blueprint, current_app, render_template, request

from spiderfoot import SpiderFootDb
from spiderfoot.services.event_service import (
    EVENT_CATEGORIES, categorize_event_summary, event_badge_color,
    human_size, dedup_events, build_event_dict, clean_source_data,
    parse_cert_fields, extract_port_service,
)

frag_bp = Blueprint('frag', __name__)

log = logging.getLogger(f"spiderfoot.{__name__}")


def _get_db():
    """Create a SpiderFootDb handle using the current app config."""
    return SpiderFootDb(current_app.config['SF_CONFIG'])


def _load_scans():
    """Return a list of scan dicts with summary counts for rendering."""
    try:
        dbh = _get_db()
        rows = dbh.scanInstanceList()
    except Exception as e:
        log.warning("Fragment: could not load scan list: %s", e)
        return []

    INLINE_TYPES = {
        'INTERNET_NAME': 'hosts',
        'IP_ADDRESS': 'IPs',
        'EMAILADDR': 'emails',
        'TCP_PORT_OPEN': 'ports',
    }

    scans = []
    for row in rows:
        scan = {
            'id': row[0],
            'name': row[1],
            'target': row[2],
            'created': row[3],
            'started': row[4],
            'ended': row[5],
            'status': row[6],
            'num_results': int(row[7] or 0),
            'type_counts': [],
            'progress': None,
        }

        try:
            summary = dbh.scanResultSummary(scan['id'], 'type')
            counts = []
            for s in summary:
                etype = s[0]
                total = int(s[3] or 0)
                if etype in INLINE_TYPES and total > 0:
                    counts.append({'label': INLINE_TYPES[etype], 'count': total})
            scan['type_counts'] = sorted(counts, key=lambda x: -x['count'])[:3]
        except Exception:
            pass

        status = (scan['status'] or '').upper()
        if status == 'RUNNING':
            try:
                mod_summary = dbh.scanResultSummary(scan['id'], 'module')
                scan['progress'] = min(95, max(5, len(mod_summary) * 3))
            except Exception:
                pass

        scans.append(scan)
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

        # Build findings from correlations (table may not exist in older DBs)
        findings = []
        try:
            correlations = dbh.scanCorrelationList(scan_id)
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
        except Exception as e:
            log.debug("Could not load correlations for %s: %s", scan_id, e)

        categories = categorize_event_summary(event_summary)

        return render_template(
            'fragments/results_summary.html',
            findings=findings,
            event_summary=event_summary,
            categories=categories,
        )

    elif tab == 'data':
        # Event rows are fetched client-side via /frag/events (respects stored
        # view mode, dedup, sort from localStorage). We only need the filter
        # dropdown and category chips for the controls shell.
        try:
            event_types = dbh.scanResultSummary(scan_id, 'type')
        except Exception:
            event_types = []

        type_count_map = {}
        for et in event_types:
            type_count_map[et[0]] = int(et[3] or 0)

        cat_chips = []
        total_all = sum(type_count_map.values())
        cat_chips.append({'key': '', 'label': 'All', 'count': total_all})
        for cat_key, cat_info in EVENT_CATEGORIES.items():
            count = sum(type_count_map.get(t, 0) for t in cat_info['types'])
            if count > 0:
                cat_chips.append({'key': cat_key, 'label': cat_info['label'], 'count': count})

        return render_template(
            'components/event_table.html',
            event_types=event_types,
            scan_id=scan_id,
            cat_chips=cat_chips,
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

    elif tab == 'log':
        try:
            logs_raw = dbh.scanLogs(scan_id, limit=200, reverse=True)
        except Exception:
            logs_raw = []

        logs = []
        for row in logs_raw:
            raw_ts = row[0] / 1000 if row and row[0] else 0
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(raw_ts)) if raw_ts else ''
            logs.append({
                'time': ts,
                'component': row[1] if len(row) > 1 else '',
                'type': row[2] if len(row) > 2 else 'INFO',
                'message': row[3] if len(row) > 3 else '',
            })

        # Check if scan is still running — scanInstanceGet returns
        # (name, target, created, started, ended, status)
        scan_data = dbh.scanInstanceGet(scan_id)
        is_running = (
            scan_data
            and len(scan_data) > 5
            and scan_data[5] in ('RUNNING', 'STARTING', 'STARTED')
        )

        return render_template(
            'fragments/results_log.html',
            logs=logs,
            scan_id=scan_id,
            is_running=is_running,
        )

    return '<p class="text-sm text-slate-400 p-8 text-center">Unknown tab.</p>'


@frag_bp.route('/log-lines')
def log_lines():
    """Return just the log line divs for HTMX polling (no wrapper)."""
    scan_id = request.args.get('id', '')
    dbh = _get_db()

    try:
        logs_raw = dbh.scanLogs(scan_id, limit=200, reverse=True)
    except Exception:
        logs_raw = []

    logs = []
    for row in logs_raw:
        raw_ts = row[0] / 1000 if row and row[0] else 0
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(raw_ts)) if raw_ts else ''
        logs.append({
            'time': ts,
            'component': row[1] if len(row) > 1 else '',
            'type': row[2] if len(row) > 2 else 'INFO',
            'message': row[3] if len(row) > 3 else '',
        })

    return render_template('fragments/log_lines.html', logs=logs)


@frag_bp.route('/events')
def events_fragment():
    """Return filtered event table rows (HTMX swap target for search/filter)."""
    scan_id = request.args.get('id', '')
    type_filter = request.args.get('type_filter', 'ALL')
    category_filter = request.args.get('category', '')
    query = request.args.get('q', '').strip().lower()
    sort_by = request.args.get('sort', 'data')
    group_by = request.args.get('group_by', '')
    dedup = request.args.get('dedup', '1')  # Default: deduplicated
    try:
        page = int(request.args.get('page', 1))
    except (ValueError, TypeError):
        page = 1
    per_page = 50

    if not scan_id:
        return ''

    dbh = _get_db()

    # If category filter is set, expand to type codes
    if category_filter and category_filter in EVENT_CATEGORIES:
        allowed_types = set(EVENT_CATEGORIES[category_filter]['types'].keys())
    else:
        allowed_types = None

    try:
        raw_events = dbh.scanResultEvent(scan_id, type_filter or 'ALL')
    except Exception:
        raw_events = []

    events = []
    for e in raw_events:
        etype = e[4]
        data_str = str(e[1] or '')
        source_str = str(e[2] or '')

        # Apply category filter
        if allowed_types and etype not in allowed_types:
            continue

        # Apply search filter (also searches source_data for URL context)
        if query:
            searchable = f"{data_str} {e[3] or ''} {e[10] or etype} {source_str}".lower()
            if query not in searchable:
                continue

        events.append(build_event_dict(e))

    # Sorting
    _SORT_KEYS = {
        'data': lambda ev: (ev['data'] or '').lower(),
        'date': lambda ev: ev['generated'] or 0,
        'module': lambda ev: (ev['module'] or '').lower(),
        'type': lambda ev: (ev['type'] or '').lower(),
        'confidence': lambda ev: ev['confidence'] or 0,
    }
    sort_fn = _SORT_KEYS.get(sort_by, _SORT_KEYS['data'])
    reverse = sort_by in ('date', 'confidence')
    events.sort(key=sort_fn, reverse=reverse)

    raw_count = len(events)

    # Deduplicate: aggregate identical (type, data) into single rows
    if dedup == '1':
        events = dedup_events(events)

    total_count = len(events)

    # Grouped view
    if group_by in ('module', 'type'):
        groups = OrderedDict()
        for evt in events:
            key = evt[group_by]
            if key not in groups:
                groups[key] = []
            groups[key].append(evt)

        grouped = []
        for key, items in groups.items():
            grouped.append({
                'label': key,
                'count': len(items),
                'events': items[:50],
                'total': len(items),
            })

        return render_template(
            'fragments/event_rows_grouped.html',
            groups=grouped,
            scan_id=scan_id,
            group_by=group_by,
            total_count=total_count,
        )

    # Flat view with pagination
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    paged_events = events[start:start + per_page]

    return render_template(
        'fragments/event_rows.html',
        events=paged_events,
        page=page,
        total_pages=total_pages,
        total_count=total_count,
        raw_count=raw_count,
        dedup=dedup,
        scan_id=scan_id,
    )


def _build_api_card_data(sf_config: dict, group_by: str = 'category') -> list:
    """Scan all modules for API key options and return a grouped list.

    Args:
        sf_config: SpiderFoot config dict with '__modules__' key
        group_by: Grouping mode — 'category' (default), 'usecase', or 'flat'

    Returns a list of dicts:
        {group, cards: [{mod_name, service_name, opt_key, value, configured}]}
    Groups are sorted with configured-first logic per group, then alphabetically.
    """

    USE_CASE_LABELS = {
        'Passive': 'Passive Recon',
        'Investigate': 'Investigation',
        'Footprint': 'Footprinting',
    }

    modules_cfg = sf_config.get('__modules__', {})
    raw_cards = []

    for mod_name, mod_cfg in modules_cfg.items():
        if mod_name.startswith('sfp__stor_'):
            continue

        meta = mod_cfg.get('meta', {})
        service_name = meta.get('name', mod_name)
        categories = meta.get('categories', [])
        use_cases = meta.get('useCases', [])
        data_source = meta.get('dataSource', {})
        website = data_source.get('website', '')
        opts = mod_cfg.get('opts', {})

        # Determine group based on grouping mode
        if group_by == 'usecase':
            group = USE_CASE_LABELS.get(use_cases[0], use_cases[0]) if use_cases else 'Other'
        elif group_by == 'flat':
            group = 'All Services'
        else:
            group = categories[0] if categories else 'Other'

        for opt_key, opt_val in opts.items():
            key_lower = opt_key.lower()
            if 'api_key' in key_lower or 'apikey' in key_lower:
                value = str(opt_val) if opt_val is not None else ''
                configured = bool(value and value.strip())
                raw_cards.append({
                    'mod_name': mod_name,
                    'service_name': service_name,
                    'opt_key': opt_key,
                    'value': value,
                    'configured': configured,
                    'group': group,
                    'website': website,
                })

    # Group cards
    groups = {}
    for card in raw_cards:
        g = card['group']
        groups.setdefault(g, []).append(card)

    # Sort cards within each group: configured first, then alphabetically
    for g in groups:
        groups[g].sort(key=lambda c: (0 if c['configured'] else 1, c['service_name'].lower()))

    # Build ordered group list, sorted alphabetically by group name
    grouped = []
    for g in sorted(groups.keys()):
        configured_count = sum(1 for c in groups[g] if c['configured'])
        grouped.append({
            'group': g,
            'cards': groups[g],
            'configured_count': configured_count,
            'total_count': len(groups[g]),
        })

    return grouped


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
        view = request.args.get('view', 'category')
        if view not in ('category', 'usecase', 'flat'):
            view = 'category'

        # Merge saved per-module opts into the module defaults
        modules_cfg = sf_config.get('__modules__', {})
        for mod_name, mod_cfg in modules_cfg.items():
            opts = mod_cfg.get('opts', {})
            for opt_key in list(opts.keys()):
                db_key = f"{mod_name}:{opt_key}"
                if db_key in saved_config:
                    opts[opt_key] = saved_config[db_key]

        groups = _build_api_card_data(sf_config, group_by=view)
        return render_template('fragments/settings_apikeys.html', groups=groups, current_view=view)

    elif section == 'proxy':
        return render_template('fragments/settings_proxy.html', config=config)

    elif section == 'database':
        db_path = sf_config.get('__database') or os.path.expanduser('~/.spiderfoot/spiderfoot.db')
        try:
            db_size = human_size(os.path.getsize(db_path))
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
