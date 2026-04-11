import base64
import hashlib
import hmac as _hmac
import logging
import os
import multiprocessing as mp
from copy import deepcopy
from datetime import datetime, timezone

from flask import Flask


def _load_passwd_file(path: str) -> dict:
    """Load username:password pairs from a passwd file.

    Args:
        path: filesystem path to the passwd file

    Returns:
        dict mapping usernames to passwords
    """
    users = {}
    try:
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ':' in line:
                    username, password = line.split(':', 1)
                    users[username.strip()] = password.strip()
    except OSError as exc:
        logging.getLogger('spiderfoot.auth').warning(
            "Cannot read passwd file %s: %s", path, exc
        )
    return users


def generate_csrf_token(secret_key: str, session_id: str) -> str:
    """Generate an HMAC-signed CSRF token."""
    return _hmac.new(
        secret_key.encode('utf-8'),
        session_id.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def create_app(config=None):
    """Flask application factory.

    Args:
        config (dict): SpiderFoot config dict (same shape as used by
                        SpiderFootWebUi). Must include '__database' for
                        SpiderFootDb, '__modules__' for module metadata, etc.

    Returns:
        Flask: configured Flask application
    """
    app = Flask(
        __name__,
        template_folder='templates',
        static_folder='static',
        static_url_path='/static'
    )

    # Default config
    app.config['SECRET_KEY'] = os.urandom(32).hex()

    # Store the live SpiderFoot config on the app so blueprints can access it
    # via current_app.config['SF_CONFIG'].
    sf_config = config or {}
    app.config['SF_CONFIG'] = sf_config
    app.config['SF_DEFAULT_CONFIG'] = deepcopy(sf_config)

    # Multiprocessing logging queue (used when launching scan processes)
    app.config.setdefault('SF_LOGGING_QUEUE', None)

    # Jinja2 custom filters
    @app.template_filter('datetimeformat')
    def datetimeformat(ts):
        """Format a Unix timestamp (seconds) as a human-readable string."""
        try:
            ts = int(ts)
            if ts <= 0:
                return '—'
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            return dt.strftime('%Y-%m-%d %H:%M')
        except (TypeError, ValueError, OSError):
            return '—'

    # Security headers
    @app.after_request
    def set_security_headers(response):
        response.headers['Server'] = 'SpiderFoot'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com blob:; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data:; "
            "font-src 'self' https://fonts.gstatic.com; "
            "frame-src 'self'; "
            "connect-src 'self'"
        )
        return response

    # Register blueprints
    from spiderfoot.blueprints.ui import ui_bp
    from spiderfoot.blueprints.api import api_bp
    from spiderfoot.blueprints.fragments import frag_bp

    app.register_blueprint(ui_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(frag_bp, url_prefix='/frag')

    # Register the API blueprint a second time at the root for backwards
    # compatibility with sfcli.py and existing JS that call endpoints
    # without the /api prefix (e.g. /scanlist, /ping, /modules).
    api_compat_bp = api_bp
    app.register_blueprint(api_compat_bp, url_prefix='/', name='api_compat')

    # --- Authentication via passwd file ---
    passwd_path = app.config.get('SF_PASSWD_FILE')
    if passwd_path is None:
        from spiderfoot.helpers import SpiderFootHelpers
        passwd_path = SpiderFootHelpers.dataPath() + '/passwd'

    users = app.config.get('SF_USERS')
    if users is None:
        users = _load_passwd_file(passwd_path)
        app.config['SF_USERS'] = users

    auth_log = logging.getLogger('spiderfoot.auth')

    @app.before_request
    def check_auth():
        from flask import request, Response

        # Exempt paths: static files and ping health check
        if request.path.startswith('/static/') or request.path in ('/api/ping', '/ping'):
            return None

        # If no users configured, auth is disabled
        if not app.config.get('SF_USERS'):
            return None

        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Basic '):
            return Response(
                'Authentication required.\n',
                401,
                {'WWW-Authenticate': 'Basic realm="SpiderFoot"'}
            )

        try:
            decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
            username, password = decoded.split(':', 1)
        except Exception:
            return Response(
                'Malformed credentials.\n',
                401,
                {'WWW-Authenticate': 'Basic realm="SpiderFoot"'}
            )

        stored_password = app.config['SF_USERS'].get(username)
        if stored_password is None:
            # Dummy comparison to prevent username-enumeration via timing
            _hmac.compare_digest("dummy", password)
            auth_log.warning(f"Failed login attempt for unknown user '{username}'")
            return Response(
                'Invalid credentials.\n',
                401,
                {'WWW-Authenticate': 'Basic realm="SpiderFoot"'}
            )

        if not _hmac.compare_digest(stored_password, password):
            auth_log.warning(f"Failed login attempt for user '{username}'")
            return Response(
                'Invalid credentials.\n',
                401,
                {'WWW-Authenticate': 'Basic realm="SpiderFoot"'}
            )

        return None

    # --- CSRF protection ---
    from flask import session, request as flask_request, Response as FlaskResponse

    @app.before_request
    def check_csrf():
        # Only enforce on POST requests
        if flask_request.method != 'POST':
            return None

        # Skip CSRF for API clients authenticating via Basic Auth
        if flask_request.headers.get('Authorization', '').startswith('Basic '):
            return None

        # Validate the token
        token = flask_request.headers.get('X-CSRF-Token', '')
        session_token = session.get('csrf_token', '')

        if not session_token or not _hmac.compare_digest(token, session_token):
            return FlaskResponse('CSRF token missing or invalid.\n', 403)

        return None

    @app.context_processor
    def inject_csrf_token():
        """Make csrf_token available in all templates."""
        if 'csrf_token' not in session:
            session['csrf_token'] = generate_csrf_token(
                app.config['SECRET_KEY'],
                os.urandom(16).hex()
            )
        return {'csrf_token': session['csrf_token']}

    return app
