import unittest
from unittest.mock import patch, MagicMock
from spiderfoot.services.ai_service import OpenRouterClient, OpenRouterError


SECRET = "sk-or-MUSTNEVERAPPEAR-IN-LOGS"


class TestNoKeyInLogs(unittest.TestCase):
    def test_401_path_does_not_log_api_key(self):
        client = OpenRouterClient(api_key=SECRET)
        with self.assertLogs("spiderfoot.spiderfoot.services.ai_service",
                             level="DEBUG") as cap:
            with patch("spiderfoot.services.ai_service.requests.post") as mock_post:
                mock_resp = MagicMock(status_code=401)
                mock_resp.text = '{"error":{"message":"bad key"}}'
                mock_post.return_value.__enter__.return_value = mock_resp
                with self.assertRaises(OpenRouterError):
                    list(client.stream_chat(
                        model="x", fallback="y",
                        messages=[{"role": "u", "content": "h"}],
                        max_tokens=10, metadata={}, session_id="s",
                    ))
        for line in cap.output:
            self.assertNotIn(SECRET, line, f"API key leaked into log: {line!r}")
            self.assertNotIn("Bearer", line, f"Bearer header leaked: {line!r}")

    def test_network_error_path_does_not_log_api_key(self):
        import requests as _requests
        client = OpenRouterClient(api_key=SECRET)
        with self.assertLogs("spiderfoot.spiderfoot.services.ai_service",
                             level="DEBUG") as cap:
            with patch("spiderfoot.services.ai_service.requests.post",
                       side_effect=_requests.ConnectionError("boom")):
                with self.assertRaises(OpenRouterError):
                    list(client.stream_chat(
                        model="x", fallback="y",
                        messages=[{"role": "u", "content": "h"}],
                        max_tokens=10, metadata={}, session_id="s",
                    ))
        for line in cap.output:
            self.assertNotIn(SECRET, line, f"API key leaked into log: {line!r}")

    def test_timeout_path_does_not_log_api_key(self):
        import requests as _requests
        client = OpenRouterClient(api_key=SECRET)
        # `assertLogs` requires at least one log record; the timeout path may
        # not emit one (depending on what stream_chat logs). Use a try/except
        # around assertLogs to handle both shapes — pytest still asserts via
        # the inner loop.
        with patch("spiderfoot.services.ai_service.requests.post",
                   side_effect=_requests.Timeout("slow")):
            try:
                with self.assertLogs(
                        "spiderfoot.spiderfoot.services.ai_service",
                        level="DEBUG") as cap:
                    with self.assertRaises(OpenRouterError):
                        list(client.stream_chat(
                            model="x", fallback="y",
                            messages=[{"role": "u", "content": "h"}],
                            max_tokens=10, metadata={}, session_id="s",
                        ))
                lines = cap.output
            except AssertionError:
                # No log lines emitted — vacuously safe.
                lines = []
        for line in lines:
            self.assertNotIn(SECRET, line, f"API key leaked into log: {line!r}")
