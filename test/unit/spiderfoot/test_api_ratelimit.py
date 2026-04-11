# test/unit/spiderfoot/test_api_ratelimit.py
import pytest
import base64
from unittest.mock import patch, MagicMock

from spiderfoot.app import create_app


@pytest.fixture
def app():
    app = create_app(config={
        '__database': ':memory:',
        '__modules__': {},
        '_maxscans': 2,
    })
    app.config['TESTING'] = True
    app.config['SF_USERS'] = {'admin': 'pass'}
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def _auth_headers():
    creds = base64.b64encode(b'admin:pass').decode()
    return {'Authorization': f'Basic {creds}'}


class TestScanRateLimit:
    def test_startscan_rejects_when_at_max(self, client):
        mock_db = MagicMock()
        mock_db.scanInstanceList.return_value = [
            ['id1', 'scan1', 'target1', '0', '0', 'RUNNING', '0', '0', '0'],
            ['id2', 'scan2', 'target2', '0', '0', 'STARTED', '0', '0', '0'],
        ]

        with patch('spiderfoot.blueprints.api.get_db', return_value=mock_db):
            response = client.post(
                '/api/startscan',
                data={
                    'scanname': 'test',
                    'scantarget': 'example.com',
                    'modulelist': 'sfp_dnsresolve',
                    'typelist': '',
                    'usecase': '',
                },
                headers=_auth_headers()
            )
            assert response.status_code == 429

    def test_startscan_allows_when_under_max(self, client):
        mock_db = MagicMock()
        mock_db.scanInstanceList.return_value = [
            ['id1', 'scan1', 'target1', '0', '0', 'RUNNING', '0', '0', '0'],
        ]

        with patch('spiderfoot.blueprints.api.get_db', return_value=mock_db):
            response = client.post(
                '/api/startscan',
                data={
                    'scanname': 'test',
                    'scantarget': 'example.com',
                    'modulelist': 'sfp_dnsresolve',
                    'typelist': '',
                    'usecase': '',
                },
                headers=_auth_headers()
            )
            assert response.status_code != 429
