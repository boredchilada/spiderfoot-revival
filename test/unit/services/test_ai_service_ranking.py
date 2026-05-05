import unittest
from spiderfoot.services.ai_service import (
    rank_events, truncate_event_data, estimate_tokens, fit_to_budget,
)


def _ev(etype, data, source="sfp_test", ts=0, in_correlation=False):
    return {
        "type": etype,
        "data": data,
        "source_module": source,
        "generated": ts,
        "in_correlation": in_correlation,
    }


class TestRanking(unittest.TestCase):
    def test_vulnerabilities_rank_highest(self):
        events = [
            _ev("INTERNET_NAME", "example.com", ts=100),
            _ev("VULNERABILITY_CVE_CRITICAL", "CVE-1", ts=1),
            _ev("EMAILADDR", "a@b.com", ts=200),
        ]
        ranked = rank_events(events)
        self.assertEqual(ranked[0]["type"], "VULNERABILITY_CVE_CRITICAL")

    def test_correlation_matched_outranks_recency(self):
        events = [
            _ev("INTERNET_NAME", "old.example.com", ts=1, in_correlation=True),
            _ev("INTERNET_NAME", "new.example.com", ts=999),
        ]
        ranked = rank_events(events)
        self.assertEqual(ranked[0]["data"], "old.example.com")

    def test_recency_breaks_ties(self):
        events = [
            _ev("INTERNET_NAME", "older", ts=1),
            _ev("INTERNET_NAME", "newer", ts=2),
        ]
        ranked = rank_events(events)
        self.assertEqual(ranked[0]["data"], "newer")


class TestTruncation(unittest.TestCase):
    def test_short_data_unchanged(self):
        self.assertEqual(truncate_event_data("hello", limit=512), "hello")

    def test_long_data_truncated_with_ellipsis(self):
        s = "x" * 1000
        out = truncate_event_data(s, limit=512)
        self.assertEqual(len(out), 513)  # 512 + ellipsis
        self.assertTrue(out.endswith("…"))

    def test_estimate_tokens_uses_3_5_chars_per_token(self):
        # 350 chars → ~100 tokens
        self.assertEqual(estimate_tokens("x" * 350), 100)


class TestBudget(unittest.TestCase):
    def test_fit_to_budget_drops_lowest_ranked_until_under_ceiling(self):
        # Each event ~50 tokens. Ceiling 100 tokens → keep top 2.
        events = [{"_render": "x" * 175} for _ in range(5)]
        kept, dropped = fit_to_budget(events, ceiling_tokens=100)
        self.assertEqual(len(kept), 2)
        self.assertEqual(dropped, 3)


if __name__ == "__main__":
    unittest.main()
