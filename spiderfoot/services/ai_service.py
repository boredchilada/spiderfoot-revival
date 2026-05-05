"""OpenRouter chat-completions client for SpiderFoot AI summarization.

This module wraps the OpenRouter `/api/v1/chat/completions` endpoint with
the project-specific defaults documented in the AI summarization design
spec: streaming on, low temperature, throughput-sorted provider, automatic
failover via the `models` array, and stable attribution headers.

The client is intentionally narrow: it does not know about scans,
correlations, prompts, or the database. Higher-level orchestration
lives elsewhere in the AI service package.
"""

import json
import logging
from typing import Iterator, List, Mapping, Optional

import requests


log = logging.getLogger(f"spiderfoot.{__name__}")

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
ATTRIBUTION_REFERER = "https://github.com/boredchilada/spiderfoot-revival"
ATTRIBUTION_TITLE = "SpiderFoot Revival"


class OpenRouterError(Exception):
    """Raised when OpenRouter returns a non-2xx response.

    The string form is a user-facing message — the blueprint emits it
    verbatim into the SSE error event.
    """


_STATUS_MESSAGES = {
    401: "Invalid OpenRouter API key — check Settings → AI Assistant.",
    402: "Out of OpenRouter credits — top up at openrouter.ai.",
    408: "Model took too long. Try regenerating, a smaller scan, or the other model.",
    413: "Scan too large for the model. Reduce events or try the other model.",
    422: "Request validation failed — please report this.",
    429: "Rate limited by OpenRouter. Wait a moment and try again.",
    500: "OpenRouter server error. Try again shortly.",
    502: "Upstream model is unavailable. Try the other model.",
    503: "OpenRouter service unavailable. Try again later.",
}


class OpenRouterClient:
    def __init__(self, api_key: str, timeout: int = 60):
        if not api_key:
            raise ValueError("OpenRouter API key is required")
        self._api_key = api_key
        self._timeout = timeout

    def stream_chat(
        self,
        model: str,
        fallback: str,
        messages: List[Mapping],
        max_tokens: int,
        metadata: Mapping,
        session_id: str,
        temperature: float = 0.3,
        top_p: float = 0.9,
    ) -> Iterator[dict]:
        """Stream a chat completion from OpenRouter.

        Yields a sequence of dicts:
          {"type": "token", "content": "..."}    - one per content delta
          {"type": "done",
           "model_used": "...",
           "prompt_tokens": int|None,
           "completion_tokens": int|None,
           "cost_usd": float|None}               - exactly once, on [DONE]

        Raises OpenRouterError with a user-facing message on HTTP error or
        upstream stream error before any token chunk arrives.
        """
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": ATTRIBUTION_REFERER,
            "X-Title": ATTRIBUTION_TITLE,
        }
        body = {
            "model": model,
            "models": [model, fallback] if fallback and fallback != model else [model],
            "messages": list(messages),
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "stream": True,
            "provider": {
                "sort": "throughput",
                "allow_fallbacks": True,
            },
            "metadata": dict(metadata),
            "session_id": session_id,
        }

        # Note: we never log `headers` or `body` — they contain the API key
        # and full payload. Log only the model and metadata identifiers.
        log.info("OpenRouter request: model=%s session=%s", model, session_id)

        try:
            with requests.post(
                OPENROUTER_URL,
                headers=headers,
                json=body,
                stream=True,
                timeout=self._timeout,
            ) as resp:
                if resp.status_code != 200:
                    msg = _STATUS_MESSAGES.get(
                        resp.status_code,
                        f"OpenRouter returned HTTP {resp.status_code}.",
                    )
                    raise OpenRouterError(msg)

                yield from self._iter_sse(resp)
        except requests.Timeout:
            raise OpenRouterError(
                "Model took too long. Try regenerating, a smaller scan, "
                "or the other model."
            )
        except requests.RequestException as e:
            log.warning("OpenRouter network error: %s", e)
            raise OpenRouterError(
                "Network error contacting OpenRouter. Check your connection."
            )

    @staticmethod
    def _iter_sse(resp) -> Iterator[dict]:
        model_used: Optional[str] = None
        prompt_tokens: Optional[int] = None
        completion_tokens: Optional[int] = None
        cost_usd: Optional[float] = None

        for raw in resp.iter_lines(decode_unicode=False):
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").strip()
            if not line.startswith("data:"):
                continue
            payload = line[len("data:"):].strip()
            if payload == "[DONE]":
                yield {
                    "type": "done",
                    "model_used": model_used,
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "cost_usd": cost_usd,
                }
                return
            try:
                obj = json.loads(payload)
            except json.JSONDecodeError:
                continue

            if model_used is None and obj.get("model"):
                model_used = obj["model"]

            usage = obj.get("usage")
            if usage:
                prompt_tokens = usage.get("prompt_tokens", prompt_tokens)
                completion_tokens = usage.get("completion_tokens", completion_tokens)
                cost_usd = usage.get("cost", cost_usd)

            choices = obj.get("choices") or []
            if choices:
                delta = choices[0].get("delta") or {}
                content = delta.get("content")
                if content:
                    yield {"type": "token", "content": content}


# ----------------------------------------------------------------------------
# Event ranking and prompt budget management
# ----------------------------------------------------------------------------

# Tokens per character heuristic. Empirically OpenRouter's tokenizers run
# 3.3–3.7 chars/token on English+ASCII; we round to 3.5 and over-estimate
# slightly so we stay safely under the model's hard limits.
_CHARS_PER_TOKEN = 3.5

_HIGH_INTEREST_PREFIXES = (
    "VULNERABILITY_",
    "LEAKED_",
    "PASSWORD_",
)
_HIGH_INTEREST_KEYWORDS = (
    "_PASSWORD_",
    "_BREACH_",
    "_HIJACKABLE",
)


def _interest_score(event: dict) -> int:
    etype = event.get("type", "")
    if any(etype.startswith(p) for p in _HIGH_INTEREST_PREFIXES):
        base = 10000
    elif any(k in etype for k in _HIGH_INTEREST_KEYWORDS):
        base = 9000
    elif event.get("in_correlation"):
        base = 5000
    else:
        base = 0
    # Recency contributes a small bump (newer wins ties).
    return base + int(event.get("generated", 0))


def rank_events(events: list) -> list:
    """Return events sorted highest-interest-first (stable for ties)."""
    return sorted(events, key=_interest_score, reverse=True)


def truncate_event_data(data: str, limit: int = 512) -> str:
    """Truncate per-event data with a trailing ellipsis if over the limit."""
    if data is None:
        return ""
    if len(data) <= limit:
        return data
    return data[:limit] + "…"


def estimate_tokens(text: str) -> int:
    """Cheap token estimator (chars / 3.5). Over-estimates slightly."""
    if not text:
        return 0
    return int(len(text) / _CHARS_PER_TOKEN)


def fit_to_budget(rendered_events: list, ceiling_tokens: int) -> tuple:
    """Drop lowest-ranked events until total estimated tokens ≤ ceiling.

    Each item must have a ``_render`` key holding its rendered string.
    Input is assumed already ranked (highest-interest first).

    Returns (kept_events, dropped_count).
    """
    total = 0
    kept = []
    for ev in rendered_events:
        cost = estimate_tokens(ev["_render"])
        if total + cost > ceiling_tokens:
            break
        kept.append(ev)
        total += cost
    return kept, len(rendered_events) - len(kept)
