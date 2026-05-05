import os
import tempfile
import unittest
from spiderfoot import SpiderFootDb
from spiderfoot.services.ai_persistence import (
    upsert_summary, fetch_cached, fetch_models_for_scan, fetch_monthly_cost,
)


class TestAiPersistence(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.opts = {'__database': os.path.join(self.tmpdir, 't.db')}
        self.dbh = SpiderFootDb(self.opts, init=True)

    def test_upsert_inserts_then_replaces_on_same_key(self):
        upsert_summary(self.dbh, scan_id='s1', kind='scan', target_id='',
                       model_requested='moonshotai/kimi-k2.6',
                       model_used='moonshotai/kimi-k2.6', content='first',
                       status='complete', scan_ended=100,
                       prompt_tokens=10, completion_tokens=20, cost_usd=0.001,
                       truncation_note=None)
        upsert_summary(self.dbh, scan_id='s1', kind='scan', target_id='',
                       model_requested='moonshotai/kimi-k2.6',
                       model_used='z-ai/glm-5.1', content='second',
                       status='complete', scan_ended=100,
                       prompt_tokens=11, completion_tokens=22, cost_usd=0.002,
                       truncation_note='3 events omitted')
        cached = fetch_cached(self.dbh, scan_id='s1', kind='scan',
                              target_id='', model_requested='moonshotai/kimi-k2.6')
        self.assertEqual(cached['content'], 'second')
        self.assertEqual(cached['model_used'], 'z-ai/glm-5.1')
        self.assertEqual(cached['truncation_note'], '3 events omitted')

    def test_fetch_cached_invalidates_on_scan_ended_mismatch(self):
        upsert_summary(self.dbh, scan_id='s1', kind='scan', target_id='',
                       model_requested='m', model_used='m', content='x',
                       status='complete', scan_ended=100,
                       prompt_tokens=1, completion_tokens=1, cost_usd=0.0,
                       truncation_note=None)
        cached = fetch_cached(self.dbh, scan_id='s1', kind='scan',
                              target_id='', model_requested='m',
                              current_scan_ended=200)
        self.assertIsNone(cached, "stale cache should not be returned")

    def test_fetch_models_for_scan_returns_all_cached(self):
        for model in ('moonshotai/kimi-k2.6', 'z-ai/glm-5.1'):
            upsert_summary(self.dbh, scan_id='s1', kind='scan', target_id='',
                           model_requested=model, model_used=model, content='x',
                           status='complete', scan_ended=100,
                           prompt_tokens=1, completion_tokens=1, cost_usd=0.0,
                           truncation_note=None)
        models = fetch_models_for_scan(self.dbh, scan_id='s1', kind='scan',
                                       target_id='')
        self.assertEqual(set(m['model_requested'] for m in models),
                         {'moonshotai/kimi-k2.6', 'z-ai/glm-5.1'})

    def test_fetch_monthly_cost_coalesces_null(self):
        upsert_summary(self.dbh, scan_id='s1', kind='scan', target_id='',
                       model_requested='m', model_used='m', content='x',
                       status='partial', scan_ended=100,
                       prompt_tokens=1, completion_tokens=1, cost_usd=None,
                       truncation_note=None)
        # Should not raise on NULL
        cost = fetch_monthly_cost(self.dbh, since_unix=0)
        self.assertEqual(cost, 0.0)
