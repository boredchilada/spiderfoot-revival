"""AI summarization SSE blueprint.

Exposes:
  GET /frag/scan/<scan_id>/summary?model=...&regenerate=1
  GET /frag/correlation/<correlation_id>/explain?model=...&regenerate=1

Both stream Server-Sent Events with `event: token` per content chunk and a
final `event: done` or `event: error`. CSRF is intentionally skipped on
these GET routes (native EventSource cannot send custom headers); auth is
inherited from the Flask session and we additionally enforce same-origin
when the Sec-Fetch-Site header is present.
"""

import logging
from collections import Counter

from flask import (
    Blueprint, Response, abort, current_app, request, stream_with_context,
)

from spiderfoot import SpiderFootDb
from spiderfoot.services import ai_service
from spiderfoot.services.ai_persistence import (
    fetch_cached, upsert_summary,
)


log = logging.getLogger(f"spiderfoot.{__name__}")
ai_bp = Blueprint('ai', __name__)


_SSE_HEADERS = {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",
    "Connection": "keep-alive",
}


def _get_db():
    return SpiderFootDb(current_app.config['SF_CONFIG'])


def _ai_config():
    cfg = current_app.config['SF_CONFIG']
    return {
        "enabled": bool(cfg.get('_ai_enabled')),
        "key": cfg.get('_ai_openrouter_key', ''),
        "default": cfg.get('_ai_default_model', 'moonshotai/kimi-k2.6'),
        "fallback": cfg.get('_ai_fallback_model', 'z-ai/glm-5.1'),
        "redact": bool(cfg.get('_ai_redact_pii')),
    }


def _ensure_enabled_or_abort():
    if not _ai_config()["enabled"]:
        abort(404)


def _enforce_same_origin():
    """Enforce that this SSE call is same-origin.

    Modern browsers send `Sec-Fetch-Site: same-origin` for fetch/EventSource
    calls from the same site. Older clients omit it — fall back to
    Origin/Referer comparison against the request's host. Without this,
    cross-origin pages could trigger OpenRouter billing via tag-based GETs.
    """
    sfs = request.headers.get('Sec-Fetch-Site')
    if sfs is not None:
        if sfs not in ('same-origin', 'same-site'):
            abort(403)
        return

    # No Sec-Fetch-Site — fall back to Origin/Referer.
    expected_host = request.host_url.rstrip('/')
    origin = request.headers.get('Origin', '')
    referer = request.headers.get('Referer', '')
    if origin:
        if not origin.rstrip('/').startswith(expected_host):
            abort(403)
        return
    if referer:
        if not referer.startswith(expected_host):
            abort(403)
        return
    # Neither header present — reject. SSE/EventSource always sends one of
    # these from a real browser; absence indicates a non-browser client or
    # a stripped-header attack and should not trigger billable upstream calls.
    abort(403)


def _sse_format(event: str, payload: str) -> str:
    """Format an SSE event, splitting payload on newlines into multiple
    `data:` lines so the receiver reassembles the original text. Carriage
    returns are stripped because they're not part of valid SSE framing."""
    text = (payload or '').replace('\r', '')
    data_lines = '\n'.join(f"data: {line}" for line in text.split('\n'))
    return f"event: {event}\n{data_lines}\n\n"


def _emit_cached(cached: dict):
    yield _sse_format("token", cached["content"])
    yield _sse_format("done", "")


def _scan_payload(dbh, scan_id: str):
    """Return (scan, type_counts, correlations, events, scan_ended) or None
    if scan does not exist."""
    dbh.dbh.execute(
        "SELECT seed_target, status, ended FROM tbl_scan_instance WHERE guid=?",
        [scan_id],
    )
    row = dbh.dbh.fetchone()
    if not row:
        return None
    target, status, ended = row[0], row[1], row[2]

    dbh.dbh.execute(
        "SELECT type, data, module, generated, hash FROM tbl_scan_results "
        "WHERE scan_instance_id=? AND false_positive=0",
        [scan_id],
    )
    raw_events = dbh.dbh.fetchall()

    type_counts = Counter(r[0] for r in raw_events).most_common(30)
    module_count = len({r[2] for r in raw_events})

    in_corr_hashes = set()
    correlations = []
    try:
        dbh.dbh.execute(
            "SELECT id, title, rule_risk FROM tbl_scan_correlation_results "
            "WHERE scan_instance_id=?",
            [scan_id],
        )
        for cid, title, risk in dbh.dbh.fetchall():
            dbh.dbh.execute(
                "SELECT event_hash FROM tbl_scan_correlation_results_events "
                "WHERE correlation_id=?",
                [cid],
            )
            hashes = [r[0] for r in dbh.dbh.fetchall()]
            in_corr_hashes.update(hashes)
            correlations.append({
                "id": cid, "title": title,
                "severity": risk,
                "evidence": f"{len(hashes)} matched event(s)",
                "risk": risk,
            })
    except Exception:
        pass

    events = [
        {
            "type": r[0], "data": r[1], "source_module": r[2],
            "generated": r[3], "in_correlation": r[4] in in_corr_hashes,
        }
        for r in raw_events
    ]

    scan = {
        "target": target, "status": status,
        "event_count": len(raw_events), "module_count": module_count,
    }
    return scan, type_counts, correlations, events, ended


@ai_bp.route('/scan/<scan_id>/summary', methods=['GET'])
def scan_summary(scan_id: str):
    _ensure_enabled_or_abort()
    _enforce_same_origin()

    cfg = _ai_config()
    if not cfg["key"]:
        abort(400, "OpenRouter API key not configured.")

    model = request.args.get('model', cfg["default"])
    regenerate = request.args.get('regenerate') == '1'
    target_id = ''

    dbh = _get_db()
    payload = _scan_payload(dbh, scan_id)
    if payload is None:
        abort(404)
    scan, type_counts, correlations, events, scan_ended = payload

    if not regenerate:
        cached = fetch_cached(
            dbh, scan_id=scan_id, kind='scan', target_id=target_id,
            model_requested=model, current_scan_ended=scan_ended,
        )
        if cached:
            return Response(stream_with_context(_emit_cached(cached)),
                            headers=_SSE_HEADERS)

    key = (scan_id, 'scan', target_id, model)
    if not ai_service.acquire_lock(key):
        abort(409, "Summary already generating for this scan and model.")

    try:
        messages, truncation_note = ai_service.build_scan_prompt(
            scan, type_counts, correlations, events,
            max_events=200, ceiling_tokens=80000, redact=cfg["redact"],
        )
    except Exception:
        ai_service.release_lock(key)
        raise

    return _stream_response(
        dbh=dbh, scan_id=scan_id, kind='scan', target_id=target_id,
        model=model, fallback=cfg["fallback"], api_key=cfg["key"],
        messages=messages, max_tokens=1200, scan_ended=scan_ended,
        truncation_note=truncation_note, lock_key=key,
        metadata={"scan_id": scan_id, "kind": "scan"},
    )


@ai_bp.route('/correlation/<correlation_id>/explain', methods=['GET'])
def correlation_explain(correlation_id: str):
    _ensure_enabled_or_abort()
    _enforce_same_origin()

    cfg = _ai_config()
    if not cfg["key"]:
        abort(400, "OpenRouter API key not configured.")
    model = request.args.get('model', cfg["default"])
    regenerate = request.args.get('regenerate') == '1'

    dbh = _get_db()
    dbh.dbh.execute(
        "SELECT scan_instance_id, rule_id, title, rule_descr, rule_risk "
        "FROM tbl_scan_correlation_results WHERE id=?",
        [correlation_id],
    )
    row = dbh.dbh.fetchone()
    if not row:
        abort(404)
    scan_id, rule_id, title, descr, risk = row

    dbh.dbh.execute(
        "SELECT ended, seed_target FROM tbl_scan_instance WHERE guid=?",
        [scan_id],
    )
    scan_row = dbh.dbh.fetchone()
    scan_ended = scan_row[0] if scan_row else None
    target = scan_row[1] if scan_row else ''

    if not regenerate:
        cached = fetch_cached(
            dbh, scan_id=scan_id, kind='correlation', target_id=correlation_id,
            model_requested=model, current_scan_ended=scan_ended,
        )
        if cached:
            return Response(stream_with_context(_emit_cached(cached)),
                            headers=_SSE_HEADERS)

    key = (scan_id, 'correlation', correlation_id, model)
    if not ai_service.acquire_lock(key):
        abort(409)

    try:
        dbh.dbh.execute(
            "SELECT r.type, r.data, r.module, r.generated FROM tbl_scan_results r "
            "JOIN tbl_scan_correlation_results_events e ON e.event_hash = r.hash "
            "WHERE e.correlation_id=? AND r.scan_instance_id=?",
            [correlation_id, scan_id],
        )
        matched = [
            {"type": r[0], "data": r[1], "source_module": r[2],
             "generated": r[3], "in_correlation": True}
            for r in dbh.dbh.fetchall()
        ]
        rule = {
            "id": rule_id, "title": title, "description": descr,
            "severity": risk, "risk": risk,
        }
        messages, _ = ai_service.build_correlation_prompt(
            {"target": target}, rule, matched, redact=cfg["redact"],
        )
    except Exception:
        ai_service.release_lock(key)
        raise

    return _stream_response(
        dbh=dbh, scan_id=scan_id, kind='correlation', target_id=correlation_id,
        model=model, fallback=cfg["fallback"], api_key=cfg["key"],
        messages=messages, max_tokens=500, scan_ended=scan_ended,
        truncation_note=None, lock_key=key,
        metadata={"scan_id": scan_id, "kind": "correlation",
                  "correlation_id": correlation_id},
    )


def _stream_response(*, dbh, scan_id, kind, target_id, model, fallback,
                     api_key, messages, max_tokens, scan_ended,
                     truncation_note, lock_key, metadata):
    client = ai_service.OpenRouterClient(api_key=api_key, timeout=60)
    runner = ai_service.StreamRunner(
        client=client, model=model, fallback=fallback,
        messages=messages, max_tokens=max_tokens,
        metadata=metadata, session_id=scan_id,
    )

    def _generate():
        try:
            for ev in runner.run():
                if ev["type"] == "token":
                    yield _sse_format("token", ev["content"])
                elif ev["type"] == "done":
                    yield _sse_format("done", "")
                elif ev["type"] == "error":
                    yield _sse_format("error", ev["message"])
        finally:
            try:
                upsert_summary(
                    dbh,
                    scan_id=scan_id, kind=kind, target_id=target_id,
                    model_requested=model, model_used=runner.model_used,
                    content=runner.assembled, status=runner.status,
                    scan_ended=scan_ended,
                    prompt_tokens=runner.prompt_tokens,
                    completion_tokens=runner.completion_tokens,
                    cost_usd=runner.cost_usd,
                    truncation_note=truncation_note,
                )
            except Exception as e:  # noqa: BLE001
                log.warning("Failed to persist AI summary: %s", e)
            ai_service.release_lock(lock_key)

    return Response(stream_with_context(_generate()), headers=_SSE_HEADERS)
