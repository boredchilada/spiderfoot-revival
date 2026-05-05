import os
import tempfile
import unittest
from unittest.mock import patch
from spiderfoot import SpiderFootDb
from spiderfoot.app import create_app
from spiderfoot.services import ai_service


def _stub_stream(*args, **kwargs):
    yield {"type": "token", "content": "Hello "}
    yield {"type": "token", "content": "world"}
    yield {"type": "done", "model_used": kwargs.get("model"),
           "prompt_tokens": 5, "completion_tokens": 2, "cost_usd": 0.0001}


class TestAiBlueprint(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        dbpath = os.path.join(self.tmpdir, 't.db')
        config = {
            '__database': dbpath,
            '_ai_enabled': True,
            '_ai_openrouter_key': 'sk-or-test',
            '_ai_default_model': 'moonshotai/kimi-k2.6',
            '_ai_fallback_model': 'z-ai/glm-5.1',
            '_ai_redact_pii': False,
            '__modules__': {},
            '__correlationrules__': [],
        }
        # seed scan
        dbh = SpiderFootDb(config, init=True)
        dbh.dbh.execute(
            "INSERT INTO tbl_scan_instance (guid, name, seed_target, "
            "created, started, ended, status) "
            "VALUES ('s1', 'test', 'example.com', 1, 2, 100, 'FINISHED')"
        )
        dbh.conn.commit()
        self.app = create_app(config)
        self.client = self.app.test_client()

    def test_disabled_returns_404(self):
        self.app.config['SF_CONFIG']['_ai_enabled'] = False
        resp = self.client.get('/frag/scan/s1/summary?model=moonshotai/kimi-k2.6')
        self.assertIn(resp.status_code, (404, 410))

    def test_stream_writes_row_and_returns_sse(self):
        self.app.config['SF_CONFIG']['_ai_enabled'] = True
        with patch.object(ai_service.OpenRouterClient, 'stream_chat',
                          side_effect=_stub_stream):
            resp = self.client.get(
                '/frag/scan/s1/summary?model=moonshotai/kimi-k2.6',
                headers={'Sec-Fetch-Site': 'same-origin'},
                buffered=True,
            )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("event: token", body)
        self.assertIn("Hello", body)
        self.assertIn("event: done", body)

        # Row persisted
        dbh = SpiderFootDb(self.app.config['SF_CONFIG'])
        dbh.dbh.execute(
            "SELECT content, status FROM tbl_ai_summaries WHERE scan_id='s1'"
        )
        row = dbh.dbh.fetchone()
        self.assertEqual(row[0], "Hello world")
        self.assertEqual(row[1], "complete")

    def test_cache_hit_does_not_call_upstream(self):
        self.app.config['SF_CONFIG']['_ai_enabled'] = True
        from spiderfoot.services.ai_persistence import upsert_summary
        dbh = SpiderFootDb(self.app.config['SF_CONFIG'])
        upsert_summary(dbh, scan_id='s1', kind='scan', target_id='',
                       model_requested='moonshotai/kimi-k2.6',
                       model_used='moonshotai/kimi-k2.6',
                       content='cached!', status='complete', scan_ended=100,
                       prompt_tokens=1, completion_tokens=1, cost_usd=0.0,
                       truncation_note=None)

        with patch.object(ai_service.OpenRouterClient, 'stream_chat') as mock_call:
            resp = self.client.get(
                '/frag/scan/s1/summary?model=moonshotai/kimi-k2.6',
                buffered=True,
            )
            mock_call.assert_not_called()
        self.assertIn("cached!", resp.get_data(as_text=True))

    def test_concurrent_request_returns_409(self):
        self.app.config['SF_CONFIG']['_ai_enabled'] = True
        key = ('s1', 'scan', '', 'moonshotai/kimi-k2.6')
        ai_service.acquire_lock(key)
        try:
            resp = self.client.get(
                '/frag/scan/s1/summary?model=moonshotai/kimi-k2.6&regenerate=1',
                buffered=True,
            )
            self.assertEqual(resp.status_code, 409)
        finally:
            ai_service.release_lock(key)
