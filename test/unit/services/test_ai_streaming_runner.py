import unittest
from unittest.mock import patch, MagicMock
from spiderfoot.services.ai_service import StreamRunner, acquire_lock, release_lock


class TestLock(unittest.TestCase):
    def test_lock_acquire_then_release_lets_second_acquire_succeed(self):
        key = ('s1', 'scan', '', 'm')
        self.assertTrue(acquire_lock(key))
        self.assertFalse(acquire_lock(key))
        release_lock(key)
        self.assertTrue(acquire_lock(key))
        release_lock(key)


class TestStreamRunner(unittest.TestCase):
    def test_runner_assembles_tokens_and_captures_done_metadata(self):
        events = [
            {"type": "token", "content": "Hello "},
            {"type": "token", "content": "world"},
            {"type": "done", "model_used": "z-ai/glm-5.1",
             "prompt_tokens": 10, "completion_tokens": 2, "cost_usd": 0.001},
        ]

        class FakeClient:
            def stream_chat(self, **kw):
                yield from events

        runner = StreamRunner(client=FakeClient(),
                              model="m", fallback="f",
                              messages=[{"role": "u", "content": "h"}],
                              max_tokens=100,
                              metadata={}, session_id="s")
        out = list(runner.run())
        token_events = [e for e in out if e["type"] == "token"]
        done = [e for e in out if e["type"] == "done"][0]
        self.assertEqual("".join(t["content"] for t in token_events), "Hello world")
        self.assertEqual(runner.assembled, "Hello world")
        self.assertEqual(runner.model_used, "z-ai/glm-5.1")
        self.assertEqual(runner.cost_usd, 0.001)
        self.assertEqual(runner.status, "complete")

    def test_runner_marks_partial_on_mid_stream_error(self):
        from spiderfoot.services.ai_service import OpenRouterError

        class FakeClient:
            def stream_chat(self, **kw):
                yield {"type": "token", "content": "Hello"}
                raise OpenRouterError("Upstream model is unavailable.")

        runner = StreamRunner(client=FakeClient(),
                              model="m", fallback="f",
                              messages=[{"role": "u", "content": "h"}],
                              max_tokens=100, metadata={}, session_id="s")
        out = list(runner.run())
        self.assertEqual(runner.assembled, "Hello")
        self.assertEqual(runner.status, "partial")
        self.assertTrue(any(e["type"] == "error" for e in out))


if __name__ == "__main__":
    unittest.main()
