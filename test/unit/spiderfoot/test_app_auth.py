# test/unit/spiderfoot/test_app_auth.py
import pytest
import sys
import os

# Add project root to path so imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from spiderfoot.app import create_app


@pytest.fixture
def app():
    """Create a test Flask app with no auth."""
    app = create_app(config={'__database': ':memory:', '__modules__': {}})
    app.config['TESTING'] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


class TestCORSRemoved:
    def test_no_access_control_allow_origin_header(self, client):
        """After CORS removal, responses must not include ACAO header."""
        response = client.get('/api/ping', headers={'Origin': 'http://evil.com'})
        assert 'Access-Control-Allow-Origin' not in response.headers

    def test_options_preflight_has_no_cors_headers(self, client):
        """OPTIONS preflight requests must not include CORS headers (no CORS middleware)."""
        response = client.options('/api/ping', headers={
            'Origin': 'http://evil.com',
            'Access-Control-Request-Method': 'GET',
        })
        # Flask handles OPTIONS natively (returns 200 with Allow header),
        # but must not inject any CORS headers.
        assert 'Access-Control-Allow-Origin' not in response.headers
        assert 'Access-Control-Allow-Methods' not in response.headers
        assert 'Access-Control-Allow-Headers' not in response.headers
