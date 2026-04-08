import os
from flask import Flask
from flask_cors import CORS


def create_app(config=None):
    """Flask application factory."""
    app = Flask(
        __name__,
        template_folder='templates',
        static_folder='static',
        static_url_path='/static'
    )

    # Default config
    app.config['SECRET_KEY'] = os.urandom(32).hex()
    app.config['SF_CONFIG'] = config or {}

    # CORS
    CORS(app)

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
            "script-src 'self' 'unsafe-inline' blob:; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
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

    return app
