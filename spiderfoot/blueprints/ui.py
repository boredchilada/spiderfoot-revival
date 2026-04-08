import logging

from flask import Blueprint, current_app, render_template, request

from spiderfoot import SpiderFootDb
from spiderfoot.__version__ import __version__

ui_bp = Blueprint('ui', __name__)

log = logging.getLogger(f"spiderfoot.{__name__}")


def _get_db():
    """Create a SpiderFootDb handle using the current app config."""
    return SpiderFootDb(current_app.config['SF_CONFIG'])


def _build_scan_list():
    """Return (scans, stats) for the dashboard.

    scans is a list of dicts with keys:
        id, name, target, created, started, ended, status, num_results

    stats is a dict with keys: running, completed, findings
    """
    try:
        dbh = _get_db()
        rows = dbh.scanInstanceList()
    except Exception as e:
        log.warning("Could not load scan list: %s", e)
        return [], {'running': 0, 'completed': 0, 'findings': 0}

    scans = []
    running = 0
    completed = 0
    findings = 0

    for row in rows:
        # row columns from scanInstanceList():
        # 0: guid, 1: name, 2: seed_target, 3: created, 4: started, 5: ended,
        # 6: status, 7: COUNT(r.type) — num_results
        scan = {
            'id': row[0],
            'name': row[1],
            'target': row[2],
            'created': row[3],
            'started': row[4],
            'ended': row[5],
            'status': row[6],
            'num_results': int(row[7] or 0),
        }
        scans.append(scan)

        status = (scan['status'] or '').upper()
        if status == 'RUNNING':
            running += 1
        elif status == 'FINISHED':
            completed += 1
        findings += scan['num_results']

    stats = {
        'running': running,
        'completed': completed,
        'findings': findings,
    }
    return scans, stats


@ui_bp.route('/')
def dashboard():
    scans, stats = _build_scan_list()
    return render_template(
        'pages/dashboard.html',
        page_id='DASHBOARD',
        version=__version__,
        scans=scans,
        stats=stats,
    )


def _build_modules_data():
    """Build module metadata for the new-scan page.

    Returns:
        tuple: (modules, categories)
            modules    — dict keyed by module name, ready for Jinja2 tojson
            categories — sorted list of unique category strings
    """
    raw = current_app.config.get('SF_CONFIG', {}).get('__modules__', {})
    modules = {}
    category_set = set()

    for mod_name, mod_cfg in raw.items():
        # Skip internal storage modules
        if mod_name.startswith('sfp__stor_'):
            continue

        meta = mod_cfg.get('meta', {})
        use_cases = meta.get('useCases', [])
        cats = meta.get('categories', [])
        category = cats[0] if cats else 'Uncategorised'
        category_set.add(category)

        # Default enabled state: module is in 'Footprint' use case
        enabled = 'Footprint' in use_cases

        modules[mod_name] = {
            'name': meta.get('name', mod_name),
            'summary': meta.get('summary', mod_cfg.get('descr', '')),
            'category': category,
            'useCases': use_cases,
            'enabled': enabled,
        }

    categories = sorted(category_set)
    return modules, categories


@ui_bp.route('/newscan')
def newscan():
    modules, categories = _build_modules_data()
    return render_template(
        'pages/scan_new.html',
        page_id='NEWSCAN',
        version=__version__,
        modules=modules,
        categories=categories,
    )


@ui_bp.route('/scaninfo')
def scaninfo():
    scan_id = request.args.get('id', '')
    if not scan_id:
        return render_template(
            'pages/scan_results.html',
            page_id='SCANINFO',
            version=__version__,
            scan=None,
            event_summary=[],
            correlations=[],
            findings=[],
            total_events=0,
            critical_count=0,
            warning_count=0,
            module_count=0,
        )

    try:
        dbh = _get_db()
        row = dbh.scanInstanceGet(scan_id)
    except Exception as e:
        log.warning("Could not load scan instance %s: %s", scan_id, e)
        row = None

    if not row:
        return render_template(
            'pages/scan_results.html',
            page_id='SCANINFO',
            version=__version__,
            scan=None,
            event_summary=[],
            correlations=[],
            findings=[],
            total_events=0,
            critical_count=0,
            warning_count=0,
            module_count=0,
        )

    # row: (name, seed_target, created, started, ended, status)
    scan = {
        'id': scan_id,
        'name': row[0],
        'target': row[1],
        'created': row[2],
        'started': row[3],
        'ended': row[4],
        'status': row[5],
    }

    # Event summary by type: (type, event_descr, last_in, total, utotal)
    try:
        event_summary = dbh.scanResultSummary(scan_id, 'type')
    except Exception:
        event_summary = []

    # Correlations: (id, title, rule_id, rule_risk, rule_name, rule_descr, rule_logic, event_count)
    try:
        correlations = dbh.scanCorrelationList(scan_id)
    except Exception:
        correlations = []

    # Build findings from correlations
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

    # Counts
    total_events = sum(int(row[3] or 0) for row in event_summary)
    critical_count = sum(1 for f in findings if (f['risk'] or '').upper() == 'HIGH')
    warning_count = sum(1 for f in findings if (f['risk'] or '').upper() == 'MEDIUM')

    # Module count from summary by module
    try:
        mod_summary = dbh.scanResultSummary(scan_id, 'module')
        module_count = len(mod_summary)
    except Exception:
        module_count = 0

    return render_template(
        'pages/scan_results.html',
        page_id='SCANINFO',
        version=__version__,
        scan=scan,
        event_summary=event_summary,
        correlations=correlations,
        findings=findings,
        total_events=total_events,
        critical_count=critical_count,
        warning_count=warning_count,
        module_count=module_count,
    )


@ui_bp.route('/opts')
def settings():
    return render_template(
        'pages/settings.html',
        page_id='SETTINGS',
        version=__version__,
    )
