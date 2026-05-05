import os
import tempfile
import unittest
from spiderfoot import SpiderFootDb
from spiderfoot.app import create_app


SECRET_KEY_VALUE = 'sk-or-MUSTNEVERAPPEAR-IN-RESPONSE'


class TestAiKeyNotLeaked(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        config = {
            '__database': os.path.join(self.tmpdir, 't.db'),
            '_ai_openrouter_key': SECRET_KEY_VALUE,
            '_ai_enabled': True,
            '_ai_default_model': 'moonshotai/kimi-k2.6',
            '_ai_fallback_model': 'z-ai/glm-5.1',
            '_ai_redact_pii': False,
            '__modules__': {},
            '__correlationrules__': [],
        }
        SpiderFootDb(config, init=True)
        self.app = create_app(config)
        self.client = self.app.test_client()

    def _assert_not_leaked(self, path: str):
        # Try GET; many of these accept POST too — also try POST.
        for method in ('GET', 'POST'):
            r = self.client.open(path, method=method)
            if r.status_code in (404, 405):
                continue
            body = r.data.decode('utf-8', errors='replace')
            self.assertNotIn(
                SECRET_KEY_VALUE, body,
                f"OpenRouter key leaked at {method} {path} (status {r.status_code})",
            )

    def test_optsraw_does_not_leak_key(self):
        self._assert_not_leaked('/api/optsraw')

    def test_optsexport_does_not_leak_key(self):
        self._assert_not_leaked('/api/optsexport')

    def test_config_endpoint_does_not_leak_key(self):
        for path in ('/api/config', '/api/configraw'):
            self._assert_not_leaked(path)

    def test_settings_page_does_not_leak_key(self):
        # Both the page and the AI fragment should be safe.
        self._assert_not_leaked('/opts')
        self._assert_not_leaked('/frag/settings-section?section=ai')
