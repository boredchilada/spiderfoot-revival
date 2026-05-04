# test/unit/spiderfoot/test_api_presets.py
import base64
import json
import os
import shutil
import tempfile
import unittest

from spiderfoot import SpiderFootDb
from spiderfoot.app import create_app
from spiderfoot.services.preset_service import seed_builtin_presets


def _fake_modules():
    return {n: {'meta': {'useCases': ['Footprint']}} for n in [
        'sfp_dnsresolve', 'sfp_crt', 'sfp_sslcert', 'sfp_whois', 'sfp_company',
        'sfp_archiveorg', 'sfp_pageinfo', 'sfp_spider', 'sfp_email',
        'sfp_countryname', 'sfp_robtex', 'sfp_dnscommonsrv',
    ]}


# Basic Auth header bypasses CSRF check (see app.py:check_csrf). With
# SF_USERS={} the auth check is disabled, so the basic-auth header doesn't
# need to be valid — its presence alone is enough to skip CSRF.
_BYPASS_HEADERS = {
    'Authorization': 'Basic ' + base64.b64encode(b'x:x').decode(),
}


class TestPresetAPI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'api.db')
        self.db = SpiderFootDb({'__database': self.db_path}, init=True)
        self.modules = _fake_modules()
        seed_builtin_presets(self.db, self.modules)

        sf_config = {
            '__database': self.db_path,
            '__modules__': self.modules,
            '__correlationrules__': [],
            '_debug': '0',
        }
        self.app = create_app(sf_config)
        self.app.config['TESTING'] = True
        self.app.config['SF_USERS'] = {}
        self.client = self.app.test_client()

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        try:
            self.db.conn.close()
        except Exception:
            pass
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_GET_presets_lists_all(self):
        resp = self.client.get('/api/presets')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertGreaterEqual(len(data), 10)
        first = data[0]
        for k in ('id', 'name', 'kind', 'is_default', 'module_count', 'modules'):
            self.assertIn(k, first)

    def test_GET_preset_by_id(self):
        resp = self.client.get('/api/presets/builtin:quick_recon')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data['id'], 'builtin:quick_recon')
        self.assertEqual(data['kind'], 'builtin')

    def test_GET_preset_404_for_unknown(self):
        resp = self.client.get('/api/presets/user:nope')
        self.assertEqual(resp.status_code, 404)

    def test_POST_preset_creates_user_preset(self):
        resp = self.client.post(
            '/api/presets',
            json={
                'name': 'My recon',
                'description': 'tight ad-hoc set',
                'modules': ['sfp_dnsresolve', 'sfp_crt'],
            },
            headers=_BYPASS_HEADERS,
        )
        self.assertEqual(resp.status_code, 201)
        data = json.loads(resp.data)
        self.assertTrue(data['id'].startswith('user:'))
        self.assertEqual(data['name'], 'My recon')
        self.assertEqual(data['kind'], 'user')
        self.assertEqual(sorted(data['modules']), ['sfp_crt', 'sfp_dnsresolve'])

    def test_POST_preset_400_on_name_conflict(self):
        # 'Footprint' is a built-in name (case-insensitive match)
        resp = self.client.post(
            '/api/presets',
            json={'name': 'footprint', 'modules': ['sfp_crt']},
            headers=_BYPASS_HEADERS,
        )
        self.assertEqual(resp.status_code, 400)
        body = json.loads(resp.data)
        self.assertIn('already exists', body.get('error', {}).get('message', ''))

    def test_POST_preset_400_on_unknown_module(self):
        resp = self.client.post(
            '/api/presets',
            json={'name': 'Bad set', 'modules': ['sfp_nonexistent']},
            headers=_BYPASS_HEADERS,
        )
        self.assertEqual(resp.status_code, 400)

    def test_POST_preset_400_on_empty_name(self):
        resp = self.client.post(
            '/api/presets',
            json={'name': '   ', 'modules': ['sfp_crt']},
            headers=_BYPASS_HEADERS,
        )
        self.assertEqual(resp.status_code, 400)

    # ------------------------------------------------------------------
    # Update / delete / set-default helpers + tests
    # ------------------------------------------------------------------

    def _auth_headers(self):
        return _BYPASS_HEADERS

    def _create_user_preset(self, name='Mine', modules=None):
        resp = self.client.post('/api/presets', json={
            'name': name, 'modules': modules or ['sfp_crt'],
        }, headers=self._auth_headers())
        self.assertEqual(resp.status_code, 201)
        return json.loads(resp.data)['id']

    def test_PATCH_preset_updates_modules(self):
        pid = self._create_user_preset()
        resp = self.client.patch(f'/api/presets/{pid}', json={
            'name': 'Renamed', 'modules': ['sfp_dnsresolve', 'sfp_sslcert'],
        }, headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data['name'], 'Renamed')
        self.assertEqual(sorted(data['modules']), ['sfp_dnsresolve', 'sfp_sslcert'])

    def test_PATCH_preset_403_on_builtin(self):
        resp = self.client.patch('/api/presets/builtin:quick_recon', json={
            'name': 'Hijacked', 'modules': ['sfp_crt'],
        }, headers=self._auth_headers())
        self.assertEqual(resp.status_code, 403)

    def test_DELETE_preset_removes_it(self):
        pid = self._create_user_preset(name='Doomed')
        resp = self.client.delete(f'/api/presets/{pid}', headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.client.get(f'/api/presets/{pid}').status_code, 404)

    def test_DELETE_preset_403_on_builtin(self):
        resp = self.client.delete('/api/presets/builtin:quick_recon', headers=self._auth_headers())
        self.assertEqual(resp.status_code, 403)

    def test_POST_default_marks_preset_as_default(self):
        pid = self._create_user_preset()
        resp = self.client.post(f'/api/presets/{pid}/default', headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        data = json.loads(self.client.get(f'/api/presets/{pid}').data)
        self.assertTrue(data['is_default'])

    def test_POST_default_clears_prior_default(self):
        a = self._create_user_preset(name='A', modules=['sfp_crt'])
        b = self._create_user_preset(name='B', modules=['sfp_crt'])
        self.client.post(f'/api/presets/{a}/default', headers=self._auth_headers())
        self.client.post(f'/api/presets/{b}/default', headers=self._auth_headers())
        a_data = json.loads(self.client.get(f'/api/presets/{a}').data)
        b_data = json.loads(self.client.get(f'/api/presets/{b}').data)
        self.assertFalse(a_data['is_default'])
        self.assertTrue(b_data['is_default'])

    def test_DELETE_default_clears_default_flag(self):
        pid = self._create_user_preset()
        self.client.post(f'/api/presets/{pid}/default', headers=self._auth_headers())
        resp = self.client.delete('/api/presets/default', headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        data = json.loads(self.client.get(f'/api/presets/{pid}').data)
        self.assertFalse(data['is_default'])

    def test_POST_preset_400_on_long_description(self):
        long_desc = 'x' * 201
        resp = self.client.post('/api/presets', json={
            'name': 'long-desc', 'description': long_desc,
            'modules': ['sfp_crt'],
        }, headers=self._auth_headers())
        self.assertEqual(resp.status_code, 400)

    def test_PATCH_preset_400_on_long_description(self):
        pid = self._create_user_preset()
        resp = self.client.patch(f'/api/presets/{pid}', json={
            'description': 'x' * 201,
        }, headers=self._auth_headers())
        self.assertEqual(resp.status_code, 400)
