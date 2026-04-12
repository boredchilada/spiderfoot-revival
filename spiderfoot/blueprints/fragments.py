import html
import logging
import os
import re
from collections import OrderedDict

from flask import Blueprint, current_app, render_template, request
from markupsafe import Markup

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
            events.append(_build_event_dict(e))

        # Default to deduped view on initial load
        events = _dedup_events(events)

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

        events.append(_build_event_dict(e))

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
        events = _dedup_events(events)

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


_WEB_CONTENT_TYPES = ('TARGET_WEB_CONTENT', 'SEARCH_ENGINE_WEB_CONTENT')
_RAW_DATA_TYPES = ('RAW_RIR_DATA', 'RAW_DNS_RECORDS', 'RAW_FILE_META')

_TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r'<[^>]+>')

# Common port → service name mapping
_PORT_SERVICES = {
    20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
    88: 'Kerberos', 110: 'POP3', 111: 'RPC', 119: 'NNTP', 123: 'NTP',
    135: 'MSRPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS',
    143: 'IMAP', 161: 'SNMP', 162: 'SNMP-trap', 179: 'BGP',
    389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    514: 'Syslog', 515: 'LPD', 587: 'SMTP-submit', 636: 'LDAPS',
    993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1433: 'MSSQL',
    1434: 'MSSQL-browser', 1521: 'Oracle', 1723: 'PPTP',
    2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel-SSL',
    3306: 'MySQL', 3389: 'RDP', 3690: 'SVN',
    5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM', 5986: 'WinRM-SSL',
    6379: 'Redis', 6443: 'K8s-API', 8080: 'HTTP-alt', 8443: 'HTTPS-alt',
    8888: 'HTTP-alt', 9090: 'HTTP-alt', 9200: 'Elasticsearch',
    9300: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB',
}

# Certificate field extraction patterns
_CERT_FIELD_RE = re.compile(
    r'(?:Issuer:\s*(.+?)(?:\n|$))'
    r'|(?:Subject:\s*(.+?)(?:\n|$))'
    r'|(?:Not Before\s*:\s*(.+?)(?:\n|$))'
    r'|(?:Not After\s*:\s*(.+?)(?:\n|$))'
    r'|(?:Serial Number:\s*\n?\s*(.+?)(?:\n|$))'
    r'|(?:Signature Algorithm:\s*(.+?)(?:\n|$))',
    re.IGNORECASE
)

# Detect if source_data looks like HTML
_HTML_SOURCE_RE = re.compile(r'^\s*<(?:!DOCTYPE|html|head|body)', re.IGNORECASE)


def _clean_source_data(source_data):
    """Clean source_data for display — extract URL or title from HTML sources."""
    if not source_data:
        return ''

    # If it looks like a URL already, return as-is
    if source_data.startswith(('http://', 'https://', 'ftp://')):
        return source_data

    # If it looks like HTML, try to extract a useful label
    if _HTML_SOURCE_RE.match(source_data):
        # Try to extract <title>
        title_match = _TITLE_RE.search(source_data)
        if title_match:
            title = title_match.group(1).strip()
            if title:
                return f"[page: {title[:80]}]"
        return '[HTML document]'

    return source_data


def _parse_cert_fields(raw_data):
    """Extract structured fields from OpenSSL certificate text dumps.

    Returns a list of (label, value) tuples, or empty list if not cert data.
    """
    # Check if this looks like cert data
    if not ('Certificate:' in raw_data or 'Issuer:' in raw_data
            or 'Serial Number:' in raw_data or 'issuer_ca_id' in raw_data):
        return []

    # Handle Python-dict-style cert data (from crt.sh / CT logs)
    if 'issuer_ca_id' in raw_data or 'common_name' in raw_data:
        fields = []
        # Extract key fields from dict-like strings
        for key, label in [
            ('common_name', 'Common Name'),
            ('name_value', 'Name'),
            ('issuer_name', 'Issuer'),
            ('serial_number', 'Serial'),
            ('not_before', 'Not Before'),
            ('not_after', 'Not After'),
            ('entry_timestamp', 'CT Log Entry'),
        ]:
            # Match both 'key': 'value' and "key": "value" patterns
            m = re.search(
                rf"""['\"]?{key}['\"]?\s*:\s*['\"]([^'\"]+)['\"]""",
                raw_data
            )
            if m:
                fields.append((label, m.group(1).strip()))
        return fields

    # Handle OpenSSL text dump format
    fields = []
    for label, pattern in [
        ('Subject', r'Subject:\s*(.+?)(?:\n|$)'),
        ('Issuer', r'Issuer:\s*(.+?)(?:\n|$)'),
        ('Not Before', r'Not Before\s*:\s*(.+?)(?:\n|$)'),
        ('Not After', r'Not After\s*:\s*(.+?)(?:\n|$)'),
        ('Serial', r'Serial Number:\s*\n?\s*([0-9a-fA-F:]+)'),
        ('Algorithm', r'Signature Algorithm:\s*(.+?)(?:\n|$)'),
    ]:
        m = re.search(pattern, raw_data, re.IGNORECASE)
        if m:
            fields.append((label, m.group(1).strip()))

    return fields


def _extract_port_service(data, type_code):
    """For TCP_PORT_OPEN events, extract port number and return service name."""
    if type_code != 'TCP_PORT_OPEN':
        return ''
    # Data format is "IP:port"
    if ':' in data:
        try:
            port = int(data.rsplit(':', 1)[1])
            return _PORT_SERVICES.get(port, '')
        except (ValueError, IndexError):
            pass
    return ''


def _build_event_dict(e):
    """Build a template-ready event dict from a DB result tuple.

    Tuple layout: (generated, data, source_data, module, type, confidence,
                    visibility, risk, hash, source_event_hash, event_descr,
                    event_type, scan_instance_id, false_positive, parent_fp)

    All user-facing strings are html.escape()'d and wrapped in Markup() so
    Jinja2 won't double-escape them.
    """
    type_code = e[4]
    raw_data = str(e[1] or '')
    raw_source = str(e[2] or '')

    # Clean source for display (URL extraction from HTML sources)
    cleaned_source = _clean_source_data(raw_source)

    # Port → service name
    service_name = _extract_port_service(raw_data, type_code)

    # Certificate structured fields (event data)
    cert_fields = []
    if type_code in ('SSL_CERTIFICATE_RAW', 'SSL_CERTIFICATE_ISSUED',
                     'SSL_CERTIFICATE_ISSUER'):
        cert_fields = _parse_cert_fields(raw_data)

    # Certificate structured fields (source data — parent was a cert)
    source_cert_fields = _parse_cert_fields(raw_source) if raw_source else []

    evt = {
        'type': e[10] or type_code,
        'type_code': type_code,
        'data': Markup(html.escape(raw_data)),
        'module': e[3],
        'confidence': e[5],
        'risk': e[7],
        'generated': e[0] if e[0] else '',
        'badge_color': _event_badge_color(type_code),
        'source_data': Markup(html.escape(cleaned_source)),
        'source_data_raw': Markup(html.escape(raw_source[:500])),
        'is_web_content': type_code in _WEB_CONTENT_TYPES,
        'data_title': '',
        'data_plaintext': '',
        'service_name': service_name,
        'cert_fields': cert_fields,
        'source_cert_fields': source_cert_fields,
        # Dedup fields — populated later by _dedup_events()
        'dupe_count': 1,
        'dupe_sources': [],
    }

    # For web content, extract page title and plaintext excerpt
    if type_code in _WEB_CONTENT_TYPES:
        title_match = _TITLE_RE.search(raw_data)
        if title_match:
            evt['data_title'] = Markup(html.escape(title_match.group(1).strip()))
        plaintext = _TAG_RE.sub(' ', raw_data)
        plaintext = re.sub(r'\s+', ' ', plaintext).strip()
        evt['data_plaintext'] = Markup(html.escape(plaintext[:2000]))

    return evt


def _dedup_events(events):
    """Aggregate duplicate events into single rows.

    Grouping key depends on event type:
      - Web content: (type_code, data_title) — same page title = same page,
        even if the HTML body differs slightly (CSRF tokens, timestamps).
      - Everything else: (type_code, data) — exact data match.

    The primary event keeps its own source/module and gains:
      - dupe_count: total occurrences
      - dupe_sources: list of {source_data, module} from the other instances
    """
    seen = OrderedDict()  # key → index into deduped list
    deduped = []

    for evt in events:
        if evt.get('is_web_content') and evt.get('data_title'):
            # Web content: group by page title (not raw HTML body)
            key = (evt['type_code'], evt['data_title'])
        else:
            key = (evt['type_code'], evt['data'])

        if key not in seen:
            seen[key] = len(deduped)
            deduped.append(evt)
        else:
            primary = deduped[seen[key]]
            primary['dupe_count'] += 1
            # Collect source info from the duplicate
            src = evt.get('source_data', '')
            mod = evt.get('module', '')
            src_cert = evt.get('source_cert_fields', [])
            # Avoid adding identical source entries (compare src+mod only)
            if not any(d['source_data'] == src and d['module'] == mod
                       for d in primary['dupe_sources']):
                entry = {
                    'source_data': src,
                    'module': mod,
                    'source_cert_fields': src_cert,
                }
                # For web content, preserve each URL's body so users
                # can compare content across URLs.
                if evt.get('is_web_content'):
                    entry['data'] = evt.get('data', '')
                    entry['data_plaintext'] = evt.get('data_plaintext', '')
                primary['dupe_sources'].append(entry)

    return deduped


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
