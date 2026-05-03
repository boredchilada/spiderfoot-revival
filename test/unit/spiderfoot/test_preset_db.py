import os
import shutil
import tempfile
import unittest

from spiderfoot import SpiderFootDb


class TestPresetSchema(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'test.db')
        self.db = SpiderFootDb({'__database': self.db_path}, init=True)

    def tearDown(self):
        self.db.close()
        try:
            self.db.conn.close()
        except Exception:
            pass
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_preset_tables_exist_on_fresh_db(self):
        rows = self.db.dbh.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'tbl_scan_preset%'"
        ).fetchall()
        names = sorted(r[0] for r in rows)
        self.assertEqual(names, ['tbl_scan_preset', 'tbl_scan_preset_module'])

    def test_preset_default_unique_index_exists(self):
        rows = self.db.dbh.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_scan_preset_default'"
        ).fetchall()
        self.assertEqual(len(rows), 1)


class TestPresetMigration(unittest.TestCase):
    """Existing pre-presets DB must gain the new tables on next __init__."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'legacy.db')

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_preset_tables_added_on_reopen(self):
        # Create a DB, drop the preset tables to simulate legacy state
        db1 = SpiderFootDb({'__database': self.db_path}, init=True)
        db1.dbh.execute("DROP TABLE tbl_scan_preset_module")
        db1.dbh.execute("DROP TABLE tbl_scan_preset")
        db1.dbh.execute("DROP INDEX IF EXISTS idx_scan_preset_default")
        db1.conn.commit()
        db1.close()
        try:
            db1.conn.close()
        except Exception:
            pass

        # Re-open without init=True; migration probe should add them
        db2 = SpiderFootDb({'__database': self.db_path})
        try:
            rows = db2.dbh.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'tbl_scan_preset%'"
            ).fetchall()
            names = sorted(r[0] for r in rows)
            self.assertEqual(names, ['tbl_scan_preset', 'tbl_scan_preset_module'])
        finally:
            db2.close()
            try:
                db2.conn.close()
            except Exception:
                pass
