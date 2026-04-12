import base64
import hashlib
import hmac as _hmac
import logging
import os
import multiprocessing as mp
from copy import deepcopy
from datetime import datetime, timezone

import bcrypt
from flask import Flask


def _hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def _check_password(password: str, stored: str) -> bool:
    """Check a password against a stored hash (bcrypt or plaintext legacy).

    If the stored value is plaintext (not a bcrypt hash), it is compared
    directly and then auto-upgraded to bcrypt in-place via the returned
    flag.

    Returns:
        bool: True if the password matches
    """
    if stored.startswith('$2b$') or stored.startswith('$2a$'):
        return bcrypt.checkpw(password.encode('utf-8'), stored.encode('utf-8'))
    # Legacy plaintext — timing-safe comparison
    return _hmac.compare_digest(stored, password)


def _is_hashed(value: str) -> bool:
    """Check if a password value is already bcrypt-hashed."""
    return value.startswith('$2b$') or value.startswith('$2a$')


def _upgrade_passwd_file(path: str, users: dict) -> None:
    """Rewrite passwd file with bcrypt-hashed passwords."""
    try:
        lines = []
        with open(path, 'r') as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    lines.append(line)
                    continue
                if ':' in stripped:
                    username, pw = stripped.split(':', 1)
                    username = username.strip()
                    hashed = users.get(username, pw.strip())
                    lines.append(f"{username}:{hashed}\n")
                else:
                    lines.append(line)
        with open(path, 'w') as f:
            f.writelines(lines)
    except OSError as exc:
        logging.getLogger('spiderfoot.auth').warning(
            "Cannot upgrade passwd file %s: %s", path, exc
        )


def _load_passwd_file(path: str) -> dict:
    """Load username:password pairs from a passwd file.

    Passwords can be bcrypt hashes or plaintext. Plaintext passwords are
    automatically upgraded to bcrypt on first load (the file is rewritten).

    Args:
        path: filesystem path to the passwd file

    Returns:
        dict mapping usernames to bcrypt-hashed passwords
    """
    auth_log = logging.getLogger('spiderfoot.auth')
    users = {}
    needs_upgrade = False
    try:
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ':' in line:
                    username, password = line.split(':', 1)
                    username = username.strip()
                    password = password.strip()
                    if not _is_hashed(password):
                        auth_log.info(f"Upgrading plaintext password for user '{username}' to bcrypt")
                        password = _hash_password(password)
                        needs_upgrade = True
                    users[username] = password
    except OSError as exc:
        auth_log.warning("Cannot read passwd file %s: %s", path, exc)
        return users

    if needs_upgrade:
        _upgrade_passwd_file(path, users)
        auth_log.info("Passwd file upgraded — all passwords are now bcrypt-hashed")

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

    # Persist SECRET_KEY across restarts so sessions/CSRF tokens survive.
    sf_config = config or {}
    secret = sf_config.get('__secret_key') or os.environ.get('SF_SECRET_KEY')
    if not secret:
        secret = os.urandom(32).hex()
        sf_config['__secret_key'] = secret
    app.config['SECRET_KEY'] = secret
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # Store the live SpiderFoot config on the app so blueprints can access it
    # via current_app.config['SF_CONFIG'].
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

    # Tag responses from legacy root-level API routes as deprecated (RFC 8594)
    @app.after_request
    def tag_deprecated_routes(response):
        from flask import request as _req
        if _req.blueprints and 'api_compat' in _req.blueprints:
            response.headers['X-Deprecated'] = 'true; use /api/ prefix'
            response.headers['Sunset'] = '2026-12-31'
        return response

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
            # Dummy bcrypt check to prevent username-enumeration via timing
            _check_password(password, _hash_password("dummy"))
            auth_log.warning(f"Failed login attempt for unknown user '{username}'")
            return Response(
                'Invalid credentials.\n',
                401,
                {'WWW-Authenticate': 'Basic realm="SpiderFoot"'}
            )

        if not _check_password(password, stored_password):
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
