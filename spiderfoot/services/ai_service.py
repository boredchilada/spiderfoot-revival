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
    return base + int(event.get("generated") or 0)


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


# ----------------------------------------------------------------------------
# PII redaction (run on assembled prompt string when _ai_redact_pii=True)
# ----------------------------------------------------------------------------

import ipaddress
import re
from urllib.parse import urlparse, urlunparse

_EMAIL_RE = re.compile(r"\b[\w.+\-]+@[\w.\-]+\.[A-Za-z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# IPv6: rough match — colon-separated hex groups, with optional :: compression.
# We then validate via ipaddress to avoid mangling MAC addresses or version strings.
_IPV6_RE = re.compile(r"(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def _is_public_ipv4(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def _is_public_ipv6(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(ip_str)
    except ValueError:
        return False
    # For IPv6, only truly private ranges are preserved: ULA (fc00::/7),
    # link-local, loopback, unspecified, and multicast. Everything else is redacted.
    return not (ip.is_loopback or ip.is_link_local or ip.is_unspecified
                or ip.is_multicast or ip in ipaddress.IPv6Network("fc00::/7"))


def _stable_token(prefix: str, key: str, registry: dict) -> str:
    if key not in registry:
        registry[key] = f"[{prefix}-{len(registry) + 1}]"
    return registry[key]


def _redact_url(match, ipv4_tokens, ipv6_tokens) -> str:
    raw = match.group(0)
    try:
        u = urlparse(raw)
    except ValueError:
        return raw
    netloc = u.hostname or ""
    if u.port:
        netloc = f"{netloc}:{u.port}"
    if u.hostname:
        if _is_public_ipv4(u.hostname):
            netloc = _stable_token("IP", u.hostname, ipv4_tokens)
            if u.port:
                netloc = f"{netloc}:{u.port}"
        elif _is_public_ipv6(u.hostname):
            netloc = _stable_token("IP6", u.hostname, ipv6_tokens)
            if u.port:
                netloc = f"{netloc}:{u.port}"
    rebuilt = urlunparse(u._replace(netloc=netloc))
    rebuilt = _EMAIL_RE.sub(
        lambda m: f"***@{m.group(0).split('@', 1)[1]}", rebuilt
    )
    return rebuilt


def redact_payload(text: str, target: str) -> tuple:
    """Apply PII redaction to ``text`` for OpenRouter submission.

    Returns (redacted_text, mapping_dict). ``mapping_dict`` is request-scoped
    and not persisted — the caller may discard it.
    """
    ipv4_tokens: dict = {}
    ipv6_tokens: dict = {}

    # 1. URLs first (decompose so userinfo + query strings get cleaned).
    text = _URL_RE.sub(
        lambda m: _redact_url(m, ipv4_tokens, ipv6_tokens), text
    )

    # 2. Emails (anywhere remaining).
    text = _EMAIL_RE.sub(
        lambda m: f"***@{m.group(0).split('@', 1)[1]}", text
    )

    # 3. Public IPv4 → stable tokens; private/reserved preserved.
    def _ipv4_sub(m):
        ip = m.group(0)
        if _is_public_ipv4(ip):
            return _stable_token("IP", ip, ipv4_tokens)
        return ip
    text = _IPV4_RE.sub(_ipv4_sub, text)

    # 4. Public IPv6 → stable tokens.
    def _ipv6_sub(m):
        ip = m.group(0)
        if _is_public_ipv6(ip):
            return _stable_token("IP6", ip, ipv6_tokens)
        return ip
    text = _IPV6_RE.sub(_ipv6_sub, text)

    # 5. Scan-target root replacement (subdomains preserved relative).
    if target:
        target = target.strip().lower()
        # Replace `host.target` first to keep relative form, then bare target.
        sub_pattern = re.compile(
            r"\b([\w\-]+(?:\.[\w\-]+)*)\." + re.escape(target) + r"\b",
            re.IGNORECASE,
        )
        text = sub_pattern.sub(r"\1.<TARGET>", text)
        text = re.compile(r"\b" + re.escape(target) + r"\b",
                          re.IGNORECASE).sub("<TARGET>", text)

    return text, {"ipv4": ipv4_tokens, "ipv6": ipv6_tokens}


# ----------------------------------------------------------------------------
# Prompt builders
# ----------------------------------------------------------------------------

SCAN_SYSTEM_PROMPT = (
    "You are a senior threat-intelligence analyst summarizing an OSINT scan "
    "from SpiderFoot. Produce a concise executive summary (≤400 words) in "
    "markdown with these sections:\n\n"
    "1. **Target Overview** — what was scanned and at what depth\n"
    "2. **Notable Findings** — bulleted list, each with severity (HIGH/MEDIUM/LOW)\n"
    "3. **Attack Surface** — exposed services, subdomains, infrastructure\n"
    "4. **Identities & Exposure** — emails, leaked credentials, social presence\n"
    "5. **Recommended Next Steps** — concrete, prioritized actions\n\n"
    "Cite specific hostnames, IPs, CVEs, or correlation rule names from the "
    "data. Do not invent findings not present in the data. Be direct and "
    "skip filler."
)

CORRELATION_SYSTEM_PROMPT = (
    "You are a senior threat-intelligence analyst. A SpiderFoot correlation "
    "rule has fired during a scan. Explain in ≤200 words, in markdown:\n\n"
    "1. **What this means** — what pattern triggered the rule and why it matters\n"
    "2. **Evidence** — the specific events that matched\n"
    "3. **Suggested response** — concrete next steps for the defender\n\n"
    "Be direct. Do not speculate beyond the matched evidence."
)


def _render_event_line(ev: dict) -> str:
    data = truncate_event_data(ev.get("data") or "", limit=512)
    return f"  [{ev.get('type')}] {data} ({ev.get('source_module')})"


def build_scan_prompt(
    scan: dict,
    type_counts: list,
    correlations: list,
    events: list,
    *,
    max_events: int = 200,
    ceiling_tokens: int = 80000,
    redact: bool = False,
):
    """Return (messages, truncation_note).

    ``scan``: dict with keys target, status, event_count, module_count.
    ``type_counts``: list of (TYPE, count) tuples (already top-30, sorted).
    ``correlations``: list of {title, severity, evidence}.
    ``events``: full event list (will be ranked + capped + budget-fitted).
    """
    ranked = rank_events(events)[:max_events]
    rendered = [{"_render": _render_event_line(ev), **ev} for ev in ranked]
    kept, dropped = fit_to_budget(rendered, ceiling_tokens=ceiling_tokens)

    parts = [
        f"TARGET: {scan.get('target')}",
        f"SCAN STATUS: {scan.get('status')}, "
        f"{scan.get('event_count')} events from {scan.get('module_count')} modules",
        "",
        "EVENT TYPE COUNTS (top 30):",
    ]
    for etype, count in type_counts[:30]:
        parts.append(f"  {etype}: {count}")

    parts.append("")
    parts.append(f"CORRELATIONS ({len(correlations)} hits):")
    for c in correlations:
        parts.append(
            f"  - \"{c.get('title')}\" ({c.get('severity')}): {c.get('evidence')}"
        )

    parts.append("")
    parts.append(f"TOP EVENTS ({len(kept)}, ranked by interest score):")
    for ev in kept:
        parts.append(ev["_render"])

    user_content = "\n".join(parts)
    if redact:
        user_content, _ = redact_payload(user_content, target=scan.get("target") or "")

    truncation_note = (
        f"{dropped} events omitted to fit token budget" if dropped > 0 else None
    )
    return [
        {"role": "system", "content": SCAN_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ], truncation_note


def build_correlation_prompt(
    scan: dict, rule: dict, matched_events: list, *, redact: bool = False
):
    parts = [
        f"SCAN TARGET: {scan.get('target')}",
        f"CORRELATION RULE: {rule.get('id')}",
        f"RULE TITLE: {rule.get('title')}",
        f"RULE DESCRIPTION: {rule.get('description')}",
        f"SEVERITY: {rule.get('severity')}",
        f"RISK: {rule.get('risk')}",
        "",
        f"MATCHED EVENTS ({len(matched_events)}):",
    ]
    for ev in matched_events:
        parts.append(_render_event_line(ev))

    user_content = "\n".join(parts)
    if redact:
        user_content, _ = redact_payload(user_content, target=scan.get("target") or "")

    return [
        {"role": "system", "content": CORRELATION_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ], None


# ----------------------------------------------------------------------------
# Concurrency lock (process-local — multi-worker is documented as v2)
# ----------------------------------------------------------------------------

import threading

_LOCKS_GUARD = threading.Lock()
_HELD: set = set()


def acquire_lock(key: tuple) -> bool:
    """Try to acquire a per-key in-flight lock. Returns False if already held."""
    with _LOCKS_GUARD:
        if key in _HELD:
            return False
        _HELD.add(key)
        return True


def release_lock(key: tuple) -> None:
    with _LOCKS_GUARD:
        _HELD.discard(key)


# ----------------------------------------------------------------------------
# StreamRunner — drives the OpenRouter client to completion regardless of
# whether the HTTP client is still listening, so we always have something to
# persist and never waste billed tokens.
# ----------------------------------------------------------------------------


class StreamRunner:
    def __init__(self, *, client, model, fallback, messages, max_tokens,
                 metadata, session_id):
        self._client = client
        self._kw = dict(
            model=model, fallback=fallback, messages=messages,
            max_tokens=max_tokens, metadata=metadata, session_id=session_id,
        )
        self.assembled = ""
        self.model_used: Optional[str] = None
        self.prompt_tokens: Optional[int] = None
        self.completion_tokens: Optional[int] = None
        self.cost_usd: Optional[float] = None
        self.status: str = "failed"
        self.error_message: Optional[str] = None

    def run(self):
        """Generator yielding events for the HTTP layer.

        Event shapes:
          {"type": "token",  "content": "..."}
          {"type": "done"}                          - on successful [DONE]
          {"type": "error",  "message": "..."}      - on upstream failure
        """
        try:
            for ev in self._client.stream_chat(**self._kw):
                if ev["type"] == "token":
                    self.assembled += ev["content"]
                    yield ev
                elif ev["type"] == "done":
                    self.model_used = ev.get("model_used")
                    self.prompt_tokens = ev.get("prompt_tokens")
                    self.completion_tokens = ev.get("completion_tokens")
                    self.cost_usd = ev.get("cost_usd")
                    self.status = "complete"
                    yield {"type": "done"}
                    return
            # Stream ended without [DONE].
            self.status = "partial" if self.assembled else "failed"
            self.error_message = "Stream ended unexpectedly."
            yield {"type": "error", "message": self.error_message}
        except OpenRouterError as e:
            self.error_message = str(e)
            self.status = "partial" if self.assembled else "failed"
            yield {"type": "error", "message": self.error_message}
        except Exception as e:  # noqa: BLE001 — last-resort safety net
            log.warning("StreamRunner unexpected error: %s", e)
            self.error_message = "Unexpected error during summary generation."
            self.status = "partial" if self.assembled else "failed"
            yield {"type": "error", "message": self.error_message}
