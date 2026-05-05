"""DB persistence helpers for tbl_ai_summaries.

Kept separate from `ai_service.py` so the OpenRouter client and prompt
builders stay free of SQL/database concerns and can be unit-tested
without spinning up a SpiderFoot DB.
"""

import time
from typing import Optional


def upsert_summary(dbh, *, scan_id, kind, target_id, model_requested,
                   model_used, content, status, scan_ended,
                   prompt_tokens, completion_tokens, cost_usd,
                   truncation_note):
    """Insert or replace a summary row keyed by
    (scan_id, kind, target_id, model_requested).

    Implemented as DELETE + INSERT (rather than INSERT OR REPLACE) so we
    don't churn the autoincrement counter on regenerate.
    """
    with dbh.dbhLock:
        dbh.dbh.execute(
            "DELETE FROM tbl_ai_summaries WHERE scan_id=? AND kind=? "
            "AND target_id=? AND model_requested=?",
            [scan_id, kind, target_id, model_requested],
        )
        dbh.dbh.execute(
            "INSERT INTO tbl_ai_summaries "
            "(scan_id, kind, target_id, model_requested, model_used, content, "
            " status, scan_ended, prompt_tokens, completion_tokens, cost_usd, "
            " truncation_note, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [scan_id, kind, target_id, model_requested, model_used, content,
             status, scan_ended, prompt_tokens, completion_tokens, cost_usd,
             truncation_note, int(time.time())],
        )
        dbh.conn.commit()


def fetch_cached(dbh, *, scan_id, kind, target_id, model_requested,
                 current_scan_ended: Optional[int] = None):
    """Return the cached summary as a dict, or None.

    If ``current_scan_ended`` is provided and does not match the persisted
    ``scan_ended``, the cache is considered stale and None is returned.
    """
    with dbh.dbhLock:
        dbh.dbh.execute(
            "SELECT model_used, content, status, scan_ended, prompt_tokens, "
            "       completion_tokens, cost_usd, truncation_note, created_at "
            "FROM tbl_ai_summaries "
            "WHERE scan_id=? AND kind=? AND target_id=? AND model_requested=?",
            [scan_id, kind, target_id, model_requested],
        )
        row = dbh.dbh.fetchone()
    if row is None:
        return None
    if current_scan_ended is not None and row[3] != current_scan_ended:
        return None
    return {
        "model_used": row[0],
        "content": row[1],
        "status": row[2],
        "scan_ended": row[3],
        "prompt_tokens": row[4],
        "completion_tokens": row[5],
        "cost_usd": row[6],
        "truncation_note": row[7],
        "created_at": row[8],
    }


def fetch_models_for_scan(dbh, *, scan_id, kind, target_id):
    """Return all cached `(model_requested, created_at, model_used)` for one
    scan/kind/target, used to populate the model dropdown."""
    with dbh.dbhLock:
        dbh.dbh.execute(
            "SELECT model_requested, model_used, created_at "
            "FROM tbl_ai_summaries WHERE scan_id=? AND kind=? AND target_id=? "
            "ORDER BY created_at DESC",
            [scan_id, kind, target_id],
        )
        rows = dbh.dbh.fetchall()
    return [
        {"model_requested": r[0], "model_used": r[1], "created_at": r[2]}
        for r in rows
    ]


def fetch_monthly_cost(dbh, *, since_unix: int) -> float:
    """Sum of cost_usd since the given unix timestamp (NULLs treated as 0)."""
    with dbh.dbhLock:
        dbh.dbh.execute(
            "SELECT COALESCE(SUM(cost_usd), 0) FROM tbl_ai_summaries "
            "WHERE created_at >= ?",
            [since_unix],
        )
        row = dbh.dbh.fetchone()
    return float(row[0]) if row else 0.0
