import html
import re
from collections import OrderedDict

from markupsafe import Markup

# Event type -> category mapping for summary tab and filter chips
EVENT_CATEGORIES = {
    'attack_surface': {
        'label': 'Attack Surface',
        'types': {
            'INTERNET_NAME': 'subdomains',
            'INTERNET_NAME_UNRESOLVED': 'unresolved hosts',
            'IP_ADDRESS': 'IPs',
            'TCP_PORT_OPEN': 'open ports',
            'TCP_PORT_OPEN_BANNER': 'port banners',
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
            'DEVICE_TYPE': 'device types',
            'SOFTWARE_USED': 'software',
            'RAW_RIR_DATA': 'RIR records',
            'SSL_CERTIFICATE_ISSUED': 'SSL certs',
            'SSL_CERTIFICATE_ISSUER': 'cert issuers',
            'BGP_AS_MEMBER': 'ASNs',
            'COMPANY_NAME': 'companies',
            'PROVIDER_HOSTING': 'hosting providers',
            'GEOINFO': 'locations',
            'DOMAIN_WHOIS': 'WHOIS records',
            'DOMAIN_REGISTRAR': 'registrars',
            'CO_HOSTED_SITE': 'co-hosted sites',
            'CO_HOSTED_SITE_DOMAIN': 'co-hosted domains',
            'AFFILIATE_INTERNET_NAME': 'affiliate hosts',
            'AFFILIATE_DOMAIN_NAME': 'affiliate domains',
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


def categorize_event_summary(event_summary):
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


def event_badge_color(type_code: str) -> str:
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

# Common port -> service name mapping
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


def human_size(num_bytes: int) -> str:
    """Convert a byte count to a human-readable string."""
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"


def clean_source_data(source_data):
    """Clean source_data for display -- extract URL or title from HTML sources."""
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


def parse_cert_fields(raw_data):
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


def extract_port_service(data, type_code):
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


def build_event_dict(e):
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
    cleaned_source = clean_source_data(raw_source)

    # Port -> service name
    service_name = extract_port_service(raw_data, type_code)

    # Certificate structured fields (event data)
    cert_fields = []
    if type_code in ('SSL_CERTIFICATE_RAW', 'SSL_CERTIFICATE_ISSUED',
                     'SSL_CERTIFICATE_ISSUER'):
        cert_fields = parse_cert_fields(raw_data)

    # Certificate structured fields (source data -- parent was a cert)
    source_cert_fields = parse_cert_fields(raw_source) if raw_source else []

    evt = {
        'type': e[10] or type_code,
        'type_code': type_code,
        'data': Markup(html.escape(raw_data)),
        'module': e[3],
        'confidence': e[5],
        'risk': e[7],
        'generated': e[0] if e[0] else '',
        'badge_color': event_badge_color(type_code),
        'source_data': Markup(html.escape(cleaned_source)),
        'source_data_raw': Markup(html.escape(raw_source[:500])),
        'is_web_content': type_code in _WEB_CONTENT_TYPES,
        'data_title': '',
        'data_plaintext': '',
        'service_name': service_name,
        'cert_fields': cert_fields,
        'source_cert_fields': source_cert_fields,
        # Dedup fields -- populated later by dedup_events()
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


def dedup_events(events):
    """Aggregate duplicate events into single rows.

    Grouping key depends on event type:
      - Web content: (type_code, data_title) -- same page title = same page,
        even if the HTML body differs slightly (CSRF tokens, timestamps).
      - Everything else: (type_code, data) -- exact data match.

    The primary event keeps its own source/module and gains:
      - dupe_count: total occurrences
      - dupe_sources: list of {source_data, module} from the other instances
    """
    seen = OrderedDict()  # key -> index into deduped list
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
