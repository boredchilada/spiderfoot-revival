import unittest
from spiderfoot.services.ai_service import redact_payload


class TestRedaction(unittest.TestCase):
    def test_emails_masked_keep_domain(self):
        out, _ = redact_payload("contact john.doe+work@evil.example.org for info", target="example.com")
        self.assertIn("***@evil.example.org", out)
        self.assertNotIn("john.doe", out)

    def test_public_ipv4_replaced_with_stable_token(self):
        out, _ = redact_payload(
            "Connect to 8.8.8.8 then verify with 8.8.8.8 again. Also 1.1.1.1.",
            target="example.com")
        self.assertIn("[IP-1]", out)
        self.assertIn("[IP-2]", out)
        self.assertEqual(out.count("[IP-1]"), 2)
        self.assertEqual(out.count("[IP-2]"), 1)

    def test_private_ipv4_preserved(self):
        out, _ = redact_payload("Internal: 10.0.0.5 and 192.168.1.1", target="example.com")
        self.assertIn("10.0.0.5", out)
        self.assertIn("192.168.1.1", out)

    def test_ipv6_replaced(self):
        out, _ = redact_payload("server at 2001:db8::1 responded", target="example.com")
        self.assertIn("[IP6-1]", out)
        self.assertNotIn("2001:db8::1", out)

    def test_target_root_replaced_subdomains_relative(self):
        out, _ = redact_payload(
            "Found admin.example.com and api.example.com",
            target="example.com")
        self.assertIn("admin.<TARGET>", out)
        self.assertIn("api.<TARGET>", out)
        self.assertNotIn("example.com", out)

    def test_third_party_hosts_preserved(self):
        out, _ = redact_payload(
            "DNS resolved to ns1.cloudflare.com",
            target="example.com")
        self.assertIn("cloudflare.com", out)

    def test_url_userinfo_redacted(self):
        out, _ = redact_payload(
            "https://admin:secret@10.99.0.1:8443/path?email=leak@example.org",
            target="example.com")
        self.assertNotIn("admin:secret", out)
        self.assertNotIn("leak@example.org", out)
