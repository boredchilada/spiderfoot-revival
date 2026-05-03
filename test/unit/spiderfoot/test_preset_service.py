import unittest

from spiderfoot.services.preset_service import (
    validate_module_names,
    BUILTIN_PRESETS,
)


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
