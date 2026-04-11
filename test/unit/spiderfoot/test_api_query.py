# test/unit/spiderfoot/test_api_query.py
import pytest
import base64
import json

from spiderfoot.app import create_app


@pytest.fixture
def app():
    app = create_app(config={'__database': ':memory:', '__modules__': {}})
    app.config['TESTING'] = True
    app.config['SF_USERS'] = {'admin': 'pass'}
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def _auth_headers():
    creds = base64.b64encode(b'admin:pass').decode()
    return {'Authorization': f'Basic {creds}'}


class TestQueryEndpointHardening:
    def test_select_query_works(self, client):
        response = client.post(
            '/api/query',
            data={'query': 'SELECT 1 as val'},
            headers=_auth_headers()
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data[0]['val'] == 1

    def test_semicolon_rejected(self, client):
        response = client.post(
            '/api/query',
            data={'query': 'SELECT 1; DROP TABLE tbl_scan_instance'},
            headers=_auth_headers()
        )
        assert response.status_code == 400

    def test_non_select_rejected(self, client):
        response = client.post(
            '/api/query',
            data={'query': 'DROP TABLE tbl_scan_instance'},
            headers=_auth_headers()
        )
        assert response.status_code == 400

    def test_error_response_does_not_leak_internals(self, client):
        response = client.post(
            '/api/query',
            data={'query': 'SELECT * FROM nonexistent_table'},
            headers=_auth_headers()
        )
        data = json.loads(response.data)
        if len(data) > 1:
            assert 'no such table' not in str(data[1]).lower()

    def test_empty_query_returns_400(self, client):
        response = client.post(
            '/api/query',
            data={'query': ''},
            headers=_auth_headers()
        )
        assert response.status_code == 400
