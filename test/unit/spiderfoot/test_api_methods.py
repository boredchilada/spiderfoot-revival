# test/unit/spiderfoot/test_api_methods.py
import pytest

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


class TestPostOnlyEndpoints:
    """State-modifying endpoints must reject GET requests with 405."""

    @pytest.mark.parametrize("path", [
        '/api/scandelete',
        '/api/stopscan',
        '/api/startscan',
        '/api/rerunscan',
        '/api/rerunscanmulti',
        '/api/savesettingsraw',
        '/api/resultsetfp',
        '/api/vacuum',
        '/api/query',
    ])
    def test_get_returns_405(self, client, path):
        response = client.get(path)
        assert response.status_code == 405, f"GET {path} should return 405, got {response.status_code}"


class TestReadEndpointsStillAcceptGet:
    """Read-only endpoints must still accept GET for CLI compatibility."""

    @pytest.mark.parametrize("path", [
        '/api/ping',
        '/api/scanlist',
        '/api/optsraw',
    ])
    def test_get_returns_non_405(self, client, path):
        response = client.get(path)
        assert response.status_code != 405, f"GET {path} should not return 405"
