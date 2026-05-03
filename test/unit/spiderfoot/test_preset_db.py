import os
import shutil
import tempfile
import time
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


class TestPresetCRUD(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'crud.db')
        self.db = SpiderFootDb({'__database': self.db_path}, init=True)

    def tearDown(self):
        self.db.close()
        try:
            self.db.conn.close()
        except Exception:
            pass
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_presetCreate_then_presetGet_round_trip(self):
        now = int(time.time() * 1000)
        self.db.presetCreate(
            preset_id='user:abc',
            name='My recon',
            description='Quick checks',
            kind='user',
            sort_order=0,
            modules=['sfp_dnsresolve', 'sfp_crt'],
            now_ms=now,
        )
        row = self.db.presetGet('user:abc')
        self.assertIsNotNone(row)
        self.assertEqual(row['id'], 'user:abc')
        self.assertEqual(row['name'], 'My recon')
        self.assertEqual(row['description'], 'Quick checks')
        self.assertEqual(row['kind'], 'user')
        self.assertEqual(row['is_default'], 0)
        self.assertEqual(row['sort_order'], 0)
        self.assertEqual(row['created_at'], now)
        self.assertEqual(row['updated_at'], now)
        self.assertEqual(sorted(row['modules']), ['sfp_crt', 'sfp_dnsresolve'])

    def test_presetGet_returns_none_for_missing(self):
        self.assertIsNone(self.db.presetGet('user:nope'))

    def test_presetList_returns_all_sorted_by_sort_order_then_name(self):
        now = int(time.time() * 1000)
        self.db.presetCreate('builtin:b', 'Bravo',   None, 'builtin', 20, [], now)
        self.db.presetCreate('builtin:a', 'Alpha',   None, 'builtin', 10, [], now)
        self.db.presetCreate('user:z',    'Zulu',    None, 'user',     0, [], now)
        rows = self.db.presetList()
        names = [r['name'] for r in rows]
        # sort_order ascending, then name ascending; user:z has sort_order=0 (default)
        self.assertEqual(names, ['Zulu', 'Alpha', 'Bravo'])

    def test_presetUpdate_changes_name_description_modules(self):
        now = int(time.time() * 1000)
        self.db.presetCreate('user:x', 'Old', 'old desc', 'user', 0, ['sfp_a'], now)
        self.db.presetUpdate(
            preset_id='user:x',
            name='New',
            description='new desc',
            modules=['sfp_b', 'sfp_c'],
            now_ms=now + 1,
        )
        row = self.db.presetGet('user:x')
        self.assertEqual(row['name'], 'New')
        self.assertEqual(row['description'], 'new desc')
        self.assertEqual(sorted(row['modules']), ['sfp_b', 'sfp_c'])
        self.assertEqual(row['updated_at'], now + 1)
        self.assertEqual(row['created_at'], now)  # unchanged

    def test_presetDelete_removes_row_and_modules(self):
        now = int(time.time() * 1000)
        self.db.presetCreate('user:y', 'Doomed', None, 'user', 0, ['sfp_a', 'sfp_b'], now)
        self.db.presetDelete('user:y')
        self.assertIsNone(self.db.presetGet('user:y'))
        # cascade should clear the modules table too
        leftover = self.db.dbh.execute(
            "SELECT COUNT(*) FROM tbl_scan_preset_module WHERE preset_id = ?",
            ('user:y',),
        ).fetchone()[0]
        self.assertEqual(leftover, 0)
