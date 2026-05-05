import unittest
from spiderfoot.services.ai_service import build_scan_prompt, build_correlation_prompt


class TestBuildScanPrompt(unittest.TestCase):
    def test_includes_target_status_counts_correlations_events(self):
        scan = {
            "target": "example.com",
            "status": "FINISHED",
            "event_count": 100,
            "module_count": 5,
        }
        type_counts = [("INTERNET_NAME", 30), ("EMAILADDR", 5)]
        correlations = [
            {"title": "Exposed admin", "severity": "HIGH",
             "evidence": "admin.example.com + 2 leaked passwords"},
        ]
        events = [
            {"type": "VULNERABILITY_CVE_CRITICAL", "data": "CVE-1", "source_module": "sfp_nuclei",
             "generated": 1, "in_correlation": False},
            {"type": "INTERNET_NAME", "data": "api.example.com", "source_module": "sfp_dns",
             "generated": 2, "in_correlation": True},
        ]
        messages, truncation_note = build_scan_prompt(
            scan, type_counts, correlations, events,
            max_events=200, ceiling_tokens=80000, redact=False,
        )
        self.assertEqual(messages[0]["role"], "system")
        self.assertIn("threat-intelligence analyst", messages[0]["content"])
        user = messages[1]["content"]
        self.assertIn("TARGET: example.com", user)
        self.assertIn("FINISHED", user)
        self.assertIn("INTERNET_NAME: 30", user)
        self.assertIn("Exposed admin", user)
        self.assertIn("CVE-1", user)
        self.assertIsNone(truncation_note)

    def test_redaction_is_applied_when_enabled(self):
        scan = {"target": "example.com", "status": "FINISHED",
                "event_count": 1, "module_count": 1}
        events = [{"type": "EMAILADDR", "data": "x@example.com",
                   "source_module": "sfp_x", "generated": 1, "in_correlation": False}]
        messages, _ = build_scan_prompt(
            scan, [], [], events, max_events=200, ceiling_tokens=80000, redact=True,
        )
        user = messages[1]["content"]
        self.assertNotIn("x@example.com", user)
        self.assertIn("***@<TARGET>", user)

    def test_truncation_note_set_when_events_dropped(self):
        scan = {"target": "example.com", "status": "FINISHED",
                "event_count": 100, "module_count": 5}
        big = "x" * 4000  # ~1100 tokens each
        events = [{"type": "INTERNET_NAME", "data": big,
                   "source_module": "sfp_x", "generated": i, "in_correlation": False}
                  for i in range(100)]
        # Tight ceiling forces drops
        _, note = build_scan_prompt(
            scan, [], [], events, max_events=200, ceiling_tokens=2000, redact=False,
        )
        self.assertIsNotNone(note)
        self.assertIn("omitted", note)


class TestBuildCorrelationPrompt(unittest.TestCase):
    def test_includes_rule_metadata_and_matched_events(self):
        scan = {"target": "example.com"}
        rule = {"id": "exposed_admin", "title": "Exposed admin",
                "description": "Admin panel + leaked creds",
                "severity": "HIGH", "risk": "HIGH"}
        matched = [
            {"type": "INTERNET_NAME", "data": "admin.example.com",
             "source_module": "sfp_dns", "generated": 1, "in_correlation": True},
        ]
        messages, _ = build_correlation_prompt(scan, rule, matched, redact=False)
        self.assertIn("CORRELATION RULE: exposed_admin", messages[1]["content"])
        self.assertIn("admin.example.com", messages[1]["content"])
