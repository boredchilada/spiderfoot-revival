import os
import shutil
import tempfile
import time
import unittest

from spiderfoot import SpiderFootDb
from spiderfoot.services.preset_service import (
    validate_module_names,
    BUILTIN_PRESETS,
    seed_builtin_presets,
)


def _fake_modules(names):
    """Build a __modules__-shaped dict with the given module names and
    minimal useCases metadata covering all three derived presets."""
    out = {}
    for n in names:
        out[n] = {
            'name': n,
            'descr': f'fake {n}',
            'cats': ['Search Engines'],
            'group': ['Footprint', 'Investigate', 'Passive'],
            'labels': [],
            'provides': [],
            'consumes': [],
            'meta': {'useCases': ['Footprint', 'Investigate', 'Passive']},
            'object': None,
        }
    return out


class TestValidateModuleNames(unittest.TestCase):
    def test_splits_known_and_unknown(self):
        modules = {'sfp_a': {}, 'sfp_b': {}, 'sfp_c': {}}
        valid, invalid = validate_module_names(
            ['sfp_a', 'sfp_x', 'sfp_b', 'sfp_y'], modules
        )
        self.assertEqual(sorted(valid), ['sfp_a', 'sfp_b'])
        self.assertEqual(sorted(invalid), ['sfp_x', 'sfp_y'])

    def test_empty_input_returns_two_empty_lists(self):
        valid, invalid = validate_module_names([], {'sfp_a': {}})
        self.assertEqual(valid, [])
        self.assertEqual(invalid, [])

    def test_dedups_repeated_names(self):
        valid, invalid = validate_module_names(
            ['sfp_a', 'sfp_a', 'sfp_b'], {'sfp_a': {}, 'sfp_b': {}}
        )
        self.assertEqual(sorted(valid), ['sfp_a', 'sfp_b'])
        self.assertEqual(invalid, [])

    def test_preserves_first_seen_order(self):
        """Documented contract: outputs reflect first-encounter order in input."""
        modules = {'sfp_a': {}, 'sfp_b': {}, 'sfp_c': {}}
        valid, invalid = validate_module_names(
            ['sfp_c', 'sfp_x', 'sfp_a', 'sfp_y', 'sfp_b'], modules
        )
        # Insertion-order, not alphabetical
        self.assertEqual(valid, ['sfp_c', 'sfp_a', 'sfp_b'])
        self.assertEqual(invalid, ['sfp_x', 'sfp_y'])


class TestBuiltinPresets(unittest.TestCase):
    def test_has_at_least_10_entries(self):
        # 3 metadata-derived + 7 curated
        self.assertGreaterEqual(len(BUILTIN_PRESETS), 10)

    def test_all_have_required_fields(self):
        for p in BUILTIN_PRESETS:
            self.assertIn('id', p)
            self.assertIn('name', p)
            self.assertIn('sort_order', p)
            self.assertTrue(p['id'].startswith('builtin:'))
            # Each entry has either 'modules' (curated) or 'derive_from_usecase'
            self.assertTrue(
                'modules' in p or 'derive_from_usecase' in p,
                f"{p['id']} has neither modules nor derive_from_usecase",
            )

    def test_ids_are_unique(self):
        ids = [p['id'] for p in BUILTIN_PRESETS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_names_are_unique(self):
        names = [p['name'].lower() for p in BUILTIN_PRESETS]
        self.assertEqual(len(names), len(set(names)))

    def test_no_intra_preset_duplicates(self):
        """Each preset's modules list should have no repeats — duplicates
        would confuse the seeder and inflate counts."""
        for p in BUILTIN_PRESETS:
            if 'modules' in p:
                modules = p['modules']
                self.assertEqual(
                    len(modules), len(set(modules)),
                    f"{p['id']} has duplicate module entries: "
                    f"{[m for m in modules if modules.count(m) > 1]}"
                )


class TestSeedBuiltinPresets(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'seed.db')
        self.db = SpiderFootDb({'__database': self.db_path}, init=True)

    def tearDown(self):
        try:
            self.db.close()
            self.db.conn.close()
        except Exception:
            pass
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_fresh_seed_inserts_all_builtins(self):
        # Use a small set of real-looking module names; missing names get dropped
        modules = _fake_modules([
            'sfp_dnsresolve', 'sfp_crt', 'sfp_sslcert', 'sfp_whois',
            'sfp_company', 'sfp_archiveorg', 'sfp_pageinfo', 'sfp_spider',
            'sfp_email', 'sfp_countryname', 'sfp_robtex', 'sfp_dnscommonsrv',
        ])
        seed_builtin_presets(self.db, modules)
        rows = self.db.presetList()
        ids = {r['id'] for r in rows}
        self.assertIn('builtin:footprint', ids)
        self.assertIn('builtin:quick_recon', ids)
        self.assertEqual(len([r for r in rows if r['kind'] == 'builtin']), len(BUILTIN_PRESETS))

    def test_seed_is_idempotent(self):
        modules = _fake_modules(['sfp_dnsresolve', 'sfp_crt'])
        seed_builtin_presets(self.db, modules)
        first = self.db.presetList()
        seed_builtin_presets(self.db, modules)
        second = self.db.presetList()
        self.assertEqual(len(first), len(second))
        # Quick recon should have the same module set both times
        q1 = next(r for r in first if r['id'] == 'builtin:quick_recon')
        q2 = next(r for r in second if r['id'] == 'builtin:quick_recon')
        self.assertEqual(sorted(q1['modules']), sorted(q2['modules']))

    def test_seed_preserves_user_presets(self):
        now = int(time.time() * 1000)
        self.db.presetCreate('user:keep', 'Keep me', None, 'user', 0, ['sfp_a'], now)
        seed_builtin_presets(self.db, _fake_modules(['sfp_a']))
        # User preset still there
        self.assertIsNotNone(self.db.presetGet('user:keep'))

    def test_seed_drops_unknown_modules(self):
        # Quick recon references sfp_whois etc; if we feed only sfp_crt,
        # the resulting Quick recon preset should contain only sfp_crt
        modules = _fake_modules(['sfp_crt'])
        seed_builtin_presets(self.db, modules)
        q = self.db.presetGet('builtin:quick_recon')
        self.assertEqual(q['modules'], ['sfp_crt'])

    def test_seed_renames_user_preset_on_name_collision(self):
        now = int(time.time() * 1000)
        # User squats on a future built-in name
        self.db.presetCreate('user:collision', 'Quick recon', None, 'user', 0, [], now)
        seed_builtin_presets(self.db, _fake_modules(['sfp_crt']))
        renamed = self.db.presetGet('user:collision')
        self.assertEqual(renamed['name'], 'Quick recon (user)')
        builtin = self.db.presetGet('builtin:quick_recon')
        self.assertEqual(builtin['name'], 'Quick recon')
