import unittest

from spiderfoot.services.event_service import event_badge_color, EVENT_CATEGORIES


class TestEventBadgeColor(unittest.TestCase):
    def test_vulnerability_is_orange(self):
        self.assertIn("orange", event_badge_color("VULNERABILITY_CVE_CRITICAL"))

    def test_malicious_is_red(self):
        self.assertIn("red", event_badge_color("MALICIOUS_IPADDR"))

    def test_network_is_cyan(self):
        self.assertIn("cyan", event_badge_color("IP_ADDRESS"))

    def test_co_hosted_site_domain_is_not_default(self):
        # Regression: CO_HOSTED_SITE_DOMAIN is an infrastructure event but
        # matched none of the colour keywords, so it fell through to the
        # neutral slate default. It should render as a network/infra colour.
        color = event_badge_color("CO_HOSTED_SITE_DOMAIN")
        self.assertIn("cyan", color)

    def test_unknown_type_falls_back_to_slate(self):
        self.assertIn("slate", event_badge_color("SOME_UNMAPPED_TYPE"))


if __name__ == "__main__":
    unittest.main()
