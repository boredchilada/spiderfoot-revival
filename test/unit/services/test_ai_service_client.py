import unittest
from unittest.mock import patch, MagicMock
from spiderfoot.services.ai_service import OpenRouterClient, OpenRouterError


class TestOpenRouterClient(unittest.TestCase):
    def setUp(self):
        self.client = OpenRouterClient(api_key="sk-or-test", timeout=30)

    def test_request_headers_include_attribution(self):
        with patch("spiderfoot.services.ai_service.requests.post") as mock_post:
            mock_resp = MagicMock(status_code=200)
            mock_resp.iter_lines.return_value = iter([b'data: [DONE]'])
            mock_post.return_value.__enter__.return_value = mock_resp
            list(self.client.stream_chat(
                model="moonshotai/kimi-k2.6",
                fallback="z-ai/glm-5.1",
                messages=[{"role": "user", "content": "hi"}],
                max_tokens=100,
                metadata={"scan_id": "s1", "kind": "scan"},
                session_id="s1",
            ))
        kwargs = mock_post.call_args.kwargs
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer sk-or-test")
        self.assertEqual(kwargs["headers"]["HTTP-Referer"],
                         "https://github.com/boredchilada/spiderfoot-revival")
        self.assertEqual(kwargs["headers"]["X-Title"], "SpiderFoot Revival")

    def test_request_body_uses_models_array_for_failover(self):
        with patch("spiderfoot.services.ai_service.requests.post") as mock_post:
            mock_resp = MagicMock(status_code=200)
            mock_resp.iter_lines.return_value = iter([b'data: [DONE]'])
            mock_post.return_value.__enter__.return_value = mock_resp
            list(self.client.stream_chat(
                model="moonshotai/kimi-k2.6",
                fallback="z-ai/glm-5.1",
                messages=[{"role": "user", "content": "hi"}],
                max_tokens=100,
                metadata={}, session_id="x",
            ))
        body = mock_post.call_args.kwargs["json"]
        self.assertEqual(body["model"], "moonshotai/kimi-k2.6")
        self.assertEqual(body["models"],
                         ["moonshotai/kimi-k2.6", "z-ai/glm-5.1"])
        self.assertTrue(body["stream"])
        self.assertEqual(body["temperature"], 0.3)
        self.assertEqual(body["provider"]["sort"], "throughput")
        self.assertTrue(body["provider"]["allow_fallbacks"])

    def test_401_maps_to_openrouter_error(self):
        with patch("spiderfoot.services.ai_service.requests.post") as mock_post:
            mock_resp = MagicMock(status_code=401)
            mock_resp.text = '{"error":{"message":"bad key"}}'
            mock_post.return_value.__enter__.return_value = mock_resp
            with self.assertRaises(OpenRouterError) as ctx:
                list(self.client.stream_chat(
                    model="x", fallback="y", messages=[{"role": "u", "content": "h"}],
                    max_tokens=10, metadata={}, session_id="s"
                ))
            self.assertIn("Invalid OpenRouter API key", str(ctx.exception))

    def test_402_maps_to_credits_error(self):
        with patch("spiderfoot.services.ai_service.requests.post") as mock_post:
            mock_resp = MagicMock(status_code=402)
            mock_resp.text = '{}'
            mock_post.return_value.__enter__.return_value = mock_resp
            with self.assertRaises(OpenRouterError) as ctx:
                list(self.client.stream_chat(
                    model="x", fallback="y", messages=[{"role": "u", "content": "h"}],
                    max_tokens=10, metadata={}, session_id="s"
                ))
            self.assertIn("Out of OpenRouter credits", str(ctx.exception))

    def test_streaming_yields_content_deltas_and_captures_model_used(self):
        sse_lines = [
            b'data: {"choices":[{"delta":{"content":"Hello"}}],"model":"z-ai/glm-5.1"}',
            b'',
            b'data: {"choices":[{"delta":{"content":" world"}}],"model":"z-ai/glm-5.1"}',
            b'',
            b'data: {"choices":[{"delta":{}}],"usage":{"prompt_tokens":10,"completion_tokens":2,"cost":0.0001},"model":"z-ai/glm-5.1"}',
            b'',
            b'data: [DONE]',
        ]
        with patch("spiderfoot.services.ai_service.requests.post") as mock_post:
            mock_resp = MagicMock(status_code=200)
            mock_resp.iter_lines.return_value = iter(sse_lines)
            mock_post.return_value.__enter__.return_value = mock_resp
            events = list(self.client.stream_chat(
                model="moonshotai/kimi-k2.6", fallback="z-ai/glm-5.1",
                messages=[{"role": "u", "content": "h"}],
                max_tokens=10, metadata={}, session_id="s",
            ))
        tokens = [e for e in events if e["type"] == "token"]
        done = [e for e in events if e["type"] == "done"][0]
        self.assertEqual("".join(t["content"] for t in tokens), "Hello world")
        self.assertEqual(done["model_used"], "z-ai/glm-5.1")
        self.assertEqual(done["prompt_tokens"], 10)
        self.assertEqual(done["completion_tokens"], 2)
        self.assertAlmostEqual(done["cost_usd"], 0.0001)
