import html
import logging
import os

from flask import Blueprint, current_app, render_template, request

from spiderfoot import SpiderFootDb

frag_bp = Blueprint('frag', __name__)

log = logging.getLogger(f"spiderfoot.{__name__}")

# Event type → category mapping for summary tab and filter chips
EVENT_CATEGORIES = {
    'attack_surface': {
        'label': 'Attack Surface',
        'types': {
            'INTERNET_NAME': 'subdomains',
            'INTERNET_NAME_UNRESOLVED': 'unresolved hosts',
            'IP_ADDRESS': 'IPs',
            'TCP_PORT_OPEN': 'open ports',
            'UDP_PORT_OPEN': 'UDP ports',
            'DOMAIN_NAME': 'domains',
        },
    },
    'identities': {
        'label': 'Identities & Exposure',
        'types': {
            'EMAILADDR': 'emails',
            'EMAILADDR_GENERIC': 'generic emails',
            'EMAILADDR_COMPROMISED': 'breached emails',
            'USERNAME': 'usernames',
            'PHONE_NUMBER': 'phone numbers',
            'HUMAN_NAME': 'names',
            'ACCOUNT_EXTERNAL_OWNED': 'accounts',
            'SOCIAL_MEDIA': 'social profiles',
            'LEAKSITE_CONTENT': 'leak mentions',
            'DARKNET_MENTION_CONTENT': 'darknet mentions',
            'PHONE_NUMBER_COMPROMISED': 'compromised phones',
        },
    },
    'infrastructure': {
        'label': 'Infrastructure',
        'types': {
            'WEBSERVER_TECHNOLOGY': 'technologies',
            'WEBSERVER_BANNER': 'banners',
            'WEBSERVER_HTTPHEADERS': 'HTTP headers',
            'OPERATING_SYSTEM': 'OS detections',
            'SOFTWARE_USED': 'software',
            'SSL_CERTIFICATE_ISSUED': 'SSL certs',
            'SSL_CERTIFICATE_ISSUER': 'cert issuers',
            'BGP_AS_MEMBER': 'ASNs',
            'COMPANY_NAME': 'companies',
            'PROVIDER_HOSTING': 'hosting providers',
            'GEOINFO': 'locations',
            'DOMAIN_WHOIS': 'WHOIS records',
            'DOMAIN_REGISTRAR': 'registrars',
            'CO_HOSTED_SITE': 'co-hosted sites',
        },
    },
    'reputation': {
        'label': 'Reputation',
        'types': {
            'MALICIOUS_IPADDR': 'flagged IPs',
            'MALICIOUS_INTERNET_NAME': 'flagged domains',
            'MALICIOUS_AFFILIATE_IPADDR': 'flagged affiliates',
            'MALICIOUS_NETBLOCK': 'flagged netblocks',
            'MALICIOUS_SUBNET': 'flagged subnets',
            'BLACKLISTED_IPADDR': 'blacklisted IPs',
            'BLACKLISTED_INTERNET_NAME': 'blacklisted domains',
            'BLACKLISTED_AFFILIATE_IPADDR': 'blacklisted affiliates',
        },
    },
    'vulnerabilities': {
        'label': 'Vulnerabilities',
        'types': {
            'VULNERABILITY_CVE_CRITICAL': 'critical CVEs',
            'VULNERABILITY_CVE_HIGH': 'high CVEs',
            'VULNERABILITY_CVE_MEDIUM': 'medium CVEs',
            'VULNERABILITY_CVE_LOW': 'low CVEs',
            'VULNERABILITY_GENERAL': 'findings',
        },
    },
}


def _categorize_event_summary(event_summary):
    """Group event_summary tuples into categories.

    Args:
        event_summary: list of tuples (type, event_descr, last_in, total, utotal)

    Returns:
        list of dicts with key, label, items
    """
    type_lookup = {}
    for cat_key, cat_info in EVENT_CATEGORIES.items():
        for etype, friendly in cat_info['types'].items():
            type_lookup[etype] = (friendly, cat_key)

    cat_items = {k: [] for k in EVENT_CATEGORIES}
    uncategorized_items = []

    for row in event_summary:
        etype = row[0]
        count = int(row[3] or 0)
        if count == 0:
            continue

        if etype in type_lookup:
            friendly, cat_key = type_lookup[etype]
            cat_items[cat_key].append({'label': friendly, 'count': count})
        else:
            descr = row[1] or etype
            uncategorized_items.append({'label': descr, 'count': count})

    result = []
    for cat_key, cat_info in EVENT_CATEGORIES.items():
        items = cat_items[cat_key]
        if items:
            result.append({
                'key': cat_key,
                'label': cat_info['label'],
                'entries': sorted(items, key=lambda x: -x['count']),
            })

    if uncategorized_items:
        result.append({
            'key': 'other',
            'label': 'Other',
            'entries': sorted(uncategorized_items, key=lambda x: -x['count']),
        })

    return result


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

        categories = _categorize_event_summary(event_summary)

        return render_template(
            'fragments/results_summary.html',
            findings=findings,
            event_summary=event_summary,
            categories=categories,
        )

    elif tab == 'data':
        try:
            raw_events = dbh.scanResultEvent(scan_id, 'ALL')[:500]
        except Exception:
            raw_events = []

        # Build event dicts for the template
        events = []
        for e in raw_events:
            events.append({
                'type': e[10] or e[4],
                'type_code': e[4],
                'data': html.escape(str(e[1] or '')),
                'module': e[3],
                'confidence': e[5],
                'risk': e[7],
                'generated': e[0] if e[0] else '',
                'badge_color': _event_badge_color(e[4]),
            })

        # Get event types for the filter dropdown
        try:
            event_types = dbh.scanResultSummary(scan_id, 'type')
        except Exception:
            event_types = []

        # Build category chip counts
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
            events=events,
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
            raw_ts = row[0] if row else 0
            if raw_ts and raw_ts > 9999999999:
                raw_ts = raw_ts / 1000
            import time as _time
            ts = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(raw_ts)) if raw_ts else ''
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
        raw_ts = row[0] if row else 0
        if raw_ts and raw_ts > 9999999999:
            raw_ts = raw_ts / 1000
        import time as _time
        ts = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(raw_ts)) if raw_ts else ''
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
    page = int(request.args.get('page', 1))
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

        # Apply category filter
        if allowed_types and etype not in allowed_types:
            continue

        # Apply search filter
        if query and query not in data_str.lower() and query not in (e[3] or '').lower() and query not in (e[10] or etype or '').lower():
            continue

        events.append({
            'type': e[10] or etype,
            'type_code': etype,
            'data': html.escape(data_str),
            'module': e[3],
            'confidence': e[5],
            'risk': e[7],
            'generated': e[0] if e[0] else '',
            'badge_color': _event_badge_color(etype),
        })

    total_count = len(events)
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
        scan_id=scan_id,
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


def _event_badge_color(type_code: str) -> str:
    """Return Tailwind CSS classes for an event type badge color."""
    tc = type_code or ''

    # Red — malicious / blacklisted / compromised
    if 'MALICIOUS' in tc or 'BLACKLISTED' in tc or 'COMPROMISED' in tc:
        return 'bg-red-900/40 text-red-300 border border-red-500/30'

    # Orange — vulnerabilities, findings
    if 'VULNERABILITY' in tc or 'CVE' in tc:
        return 'bg-orange-900/40 text-orange-300 border border-orange-500/30'

    # Cyan — network / attack surface (IPs, domains, ports, hostnames)
    if any(k in tc for k in ('IP_ADDRESS', 'INTERNET_NAME', 'DOMAIN_NAME',
                              'TCP_PORT', 'UDP_PORT', 'NETBLOCK', 'BGP',
                              'AFFILIATE_INTERNET', 'DNS_', 'PROVIDER_')):
        return 'bg-cyan-900/40 text-cyan-300 border border-cyan-500/30'

    # Violet — identity / people (emails, usernames, names, phones, accounts)
    if any(k in tc for k in ('EMAIL', 'USERNAME', 'HUMAN_NAME', 'PHONE_NUMBER',
                              'ACCOUNT_', 'SOCIAL_MEDIA')):
        return 'bg-violet-900/40 text-violet-300 border border-violet-500/30'

    # Emerald — infrastructure / tech (web servers, SSL, software, hosting)
    if any(k in tc for k in ('WEBSERVER', 'SSL_CERTIFICATE', 'SOFTWARE',
                              'OPERATING_SYSTEM', 'HTTP_CODE', 'LINKED_URL',
                              'WEB_ANALYTICS', 'CLOUD_STORAGE')):
        return 'bg-emerald-900/40 text-emerald-300 border border-emerald-500/30'

    # Amber — reputation / threat intel
    if any(k in tc for k in ('LEAKSITE', 'DARKNET', 'DEFACED', 'RANSOMWARE')):
        return 'bg-amber-900/40 text-amber-300 border border-amber-500/30'

    # Muted slate — raw / bulk data
    if any(k in tc for k in ('TARGET_WEB_CONTENT', 'RAW_RIR_DATA', 'RAW_DNS',
                              'RAW_FILE', 'ROOT', 'SEARCH_ENGINE_WEB_CONTENT')):
        return 'bg-slate-700/40 text-slate-400 border border-slate-500/30'

    # Default — neutral
    return 'bg-slate-700/40 text-slate-400 border border-slate-500/30'


def _build_api_card_data(sf_config: dict) -> list:
    """Scan all modules for API key options and return a grouped list.

    Returns a list of dicts:
        {group, cards: [{mod_name, service_name, opt_key, value, configured}]}
    Groups are sorted with configured-first logic per group, then alphabetically.
    """
    modules_cfg = sf_config.get('__modules__', {})
    raw_cards = []

    for mod_name, mod_cfg in modules_cfg.items():
        if mod_name.startswith('sfp__stor_'):
            continue

        meta = mod_cfg.get('meta', {})
        service_name = meta.get('name', mod_name)
        categories = meta.get('categories', [])
        group = categories[0] if categories else 'Other'
        data_source = meta.get('dataSource', {})
        website = data_source.get('website', '')
        opts = mod_cfg.get('opts', {})

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

    # Group cards by category
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
        # Merge saved per-module opts into the module defaults
        modules_cfg = sf_config.get('__modules__', {})
        for mod_name, mod_cfg in modules_cfg.items():
            opts = mod_cfg.get('opts', {})
            for opt_key in list(opts.keys()):
                db_key = f"{mod_name}:{opt_key}"
                if db_key in saved_config:
                    opts[opt_key] = saved_config[db_key]

        groups = _build_api_card_data(sf_config)
        return render_template('fragments/settings_apikeys.html', groups=groups)

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
