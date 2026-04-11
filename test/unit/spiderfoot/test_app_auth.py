# test/unit/spiderfoot/test_app_auth.py
import base64
import pytest

from spiderfoot.app import create_app


@pytest.fixture
def app():
    """Create a minimal test Flask app."""
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


def _basic_auth_header(user, password):
    """Build an Authorization: Basic header value."""
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {'Authorization': f'Basic {creds}'}


@pytest.fixture
def passwd_file(tmp_path):
    """Create a temporary passwd file with one user."""
    pf = tmp_path / "passwd"
    pf.write_text("admin:secret123\n")
    return str(pf)


@pytest.fixture
def app_with_auth(passwd_file):
    """Create a test Flask app with auth enabled."""
    app = create_app(config={
        '__database': ':memory:',
        '__modules__': {},
    })
    app.config['TESTING'] = True
    app.config['SF_PASSWD_FILE'] = passwd_file
    # Re-load credentials from the file
    from spiderfoot.app import _load_passwd_file
    app.config['SF_USERS'] = _load_passwd_file(passwd_file)
    return app


@pytest.fixture
def auth_client(app_with_auth):
    return app_with_auth.test_client()


class TestBasicAuth:
    def test_unauthenticated_request_returns_401(self, auth_client):
        response = auth_client.get('/api/scanlist')
        assert response.status_code == 401
        assert 'WWW-Authenticate' in response.headers
        assert 'Basic' in response.headers['WWW-Authenticate']

    def test_valid_credentials_returns_200(self, auth_client):
        response = auth_client.get('/api/scanlist', headers=_basic_auth_header('admin', 'secret123'))
        assert response.status_code == 200

    def test_invalid_password_returns_401(self, auth_client):
        response = auth_client.get('/api/scanlist', headers=_basic_auth_header('admin', 'wrong'))
        assert response.status_code == 401

    def test_unknown_user_returns_401(self, auth_client):
        response = auth_client.get('/api/scanlist', headers=_basic_auth_header('nobody', 'secret123'))
        assert response.status_code == 401

    def test_static_files_exempt_from_auth(self, auth_client):
        """Static file requests should not require authentication."""
        response = auth_client.get('/static/js/theme.js')
        # 200 if file exists, 404 if not — but never 401
        assert response.status_code != 401

    def test_ping_exempt_from_auth(self, auth_client):
        """The /api/ping health check should not require authentication."""
        response = auth_client.get('/api/ping')
        assert response.status_code == 200

    def test_no_passwd_file_allows_all_requests(self, client):
        """When no passwd file is configured, all requests pass."""
        response = client.get('/api/scanlist')
        assert response.status_code == 200


class TestPasswdFileLoading:
    def test_load_multiple_users(self, tmp_path):
        from spiderfoot.app import _load_passwd_file
        pf = tmp_path / "passwd"
        pf.write_text("admin:pass1\nanalyst:pass2\n")
        users = _load_passwd_file(str(pf))
        assert users == {'admin': 'pass1', 'analyst': 'pass2'}

    def test_load_empty_file_returns_empty_dict(self, tmp_path):
        from spiderfoot.app import _load_passwd_file
        pf = tmp_path / "passwd"
        pf.write_text("")
        users = _load_passwd_file(str(pf))
        assert users == {}

    def test_load_skips_blank_lines_and_comments(self, tmp_path):
        from spiderfoot.app import _load_passwd_file
        pf = tmp_path / "passwd"
        pf.write_text("# comment\n\nadmin:pass1\n\n")
        users = _load_passwd_file(str(pf))
        assert users == {'admin': 'pass1'}

    def test_load_nonexistent_file_returns_empty_dict(self):
        from spiderfoot.app import _load_passwd_file
        users = _load_passwd_file('/nonexistent/passwd')
        assert users == {}
