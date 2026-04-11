import os
import multiprocessing as mp
from copy import deepcopy
from datetime import datetime, timezone

from flask import Flask


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

    # CSRF-style token for settings endpoints
    app.config.setdefault('SF_TOKEN', None)

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

    return app
