# test/unit/spiderfoot/test_app_csrf.py
import pytest
import base64
import re

from spiderfoot.app import create_app


@pytest.fixture
def app():
    app = create_app(config={'__database': ':memory:', '__modules__': {}})
    app.config['TESTING'] = True
    app.config['SF_USERS'] = {}
    return app


@pytest.fixture
def client(app):
    return app.test_client()


class TestCSRF:
    def test_get_requests_not_subject_to_csrf(self, client):
        response = client.get('/api/scanlist')
        assert response.status_code == 200

    def test_post_without_token_returns_403(self, client):
        response = client.post('/api/stopscan', data={'id': 'fake'})
        assert response.status_code == 403

    def test_post_with_valid_token_succeeds(self, client):
        # Get a page to establish session and get token
        response = client.get('/')
        html = response.data.decode()
        match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
        assert match, "CSRF token meta tag not found in page"
        token = match.group(1)

        # POST with the token — should pass CSRF (may fail on business logic, but not 403)
        response = client.post(
            '/api/stopscan',
            data={'id': 'nonexistent'},
            headers={'X-CSRF-Token': token}
        )
        assert response.status_code != 403

    def test_post_with_basic_auth_skips_csrf(self, app):
        app.config['SF_USERS'] = {'admin': 'pass'}
        client = app.test_client()
        creds = base64.b64encode(b'admin:pass').decode()
        response = client.post(
            '/api/stopscan',
            data={'id': 'fake'},
            headers={'Authorization': f'Basic {creds}'}
        )
        assert response.status_code != 403

    def test_post_with_invalid_token_returns_403(self, client):
        response = client.post(
            '/api/stopscan',
            data={'id': 'fake'},
            headers={'X-CSRF-Token': 'bogus-token-value'}
        )
        assert response.status_code == 403
