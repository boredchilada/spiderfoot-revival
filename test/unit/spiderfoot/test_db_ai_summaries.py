import os
import tempfile
import unittest
from spiderfoot import SpiderFootDb


class TestAiSummariesSchema(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.dbpath = os.path.join(self.tmpdir, "test.db")
        self.opts = {'__database': self.dbpath}
        self.dbh = SpiderFootDb(self.opts, init=True)

    def test_table_exists(self):
        self.dbh.dbh.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='tbl_ai_summaries'"
        )
        row = self.dbh.dbh.fetchone()
        self.assertIsNotNone(row, "tbl_ai_summaries should exist after init")

    def test_unique_key_dedupes_with_empty_target_id(self):
        # Empty-string sentinel for kind='scan' must be treated as a real value
        # by the UNIQUE constraint (NULL would defeat dedup).
        now = 1234567890
        self.dbh.dbh.execute(
            "INSERT INTO tbl_ai_summaries "
            "(scan_id, kind, target_id, model_requested, content, status, created_at) "
            "VALUES (?, 'scan', '', 'moonshotai/kimi-k2.6', 'first', 'complete', ?)",
            ('scan1', now)
        )
        self.dbh.conn.commit()
        with self.assertRaises(Exception):
            self.dbh.dbh.execute(
                "INSERT INTO tbl_ai_summaries "
                "(scan_id, kind, target_id, model_requested, content, status, created_at) "
                "VALUES (?, 'scan', '', 'moonshotai/kimi-k2.6', 'second', 'complete', ?)",
                ('scan1', now)
            )
            self.dbh.conn.commit()

    def test_index_exists(self):
        self.dbh.dbh.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_ai_summaries_scan'"
        )
        self.assertIsNotNone(self.dbh.dbh.fetchone())


class TestAiSummariesCascadeDelete(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.dbpath = os.path.join(self.tmpdir, "test.db")
        self.opts = {'__database': self.dbpath}
        self.dbh = SpiderFootDb(self.opts, init=True)
        # create a fake scan + summary
        self.dbh.dbh.execute(
            "INSERT INTO tbl_scan_instance (guid, name, seed_target, created, started, ended, status) "
            "VALUES ('s1', 'test', 'example.com', 1, 2, 3, 'FINISHED')"
        )
        self.dbh.dbh.execute(
            "INSERT INTO tbl_ai_summaries "
            "(scan_id, kind, target_id, model_requested, content, status, created_at) "
            "VALUES ('s1', 'scan', '', 'moonshotai/kimi-k2.6', 'x', 'complete', 1)"
        )
        self.dbh.conn.commit()

    def test_delete_cascades_to_ai_summaries(self):
        self.dbh.scanInstanceDelete('s1')
        self.dbh.dbh.execute(
            "SELECT COUNT(*) FROM tbl_ai_summaries WHERE scan_id='s1'"
        )
        count = self.dbh.dbh.fetchone()[0]
        self.assertEqual(count, 0, "AI summaries should be deleted with scan")
