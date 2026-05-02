# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ransomwarelive
# Purpose:      Check whether the target appears on a ransomware leak-site
#               via ransomware.live's free public API.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import threading
import time
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ransomwarelive(SpiderFootPlugin):

    meta = {
        "name": "Ransomware.live",
        "summary": "Check whether the target appears on any tracked ransomware leak-site (ransomware.live).",
        "flags": [],
        "useCases": ["Investigate", "Passive"],
        "categories": ["Leaks, Dumps and Breaches"],
        "dataSource": {
            "website": "https://www.ransomware.live/",
            "model": "FREE_NOAUTH_LIMITED",
            "references": [
                "https://www.ransomware.live/api",
                "https://api-pro.ransomware.live/docs",
            ],
            "favIcon": "https://www.ransomware.live/static/favicon.ico",
            "logo": "https://images.ransomware.live/logo.png",
            "description": (
                "Ransomware.live aggregates victim postings from active ransomware "
                "and data-extortion leak sites. The free v2 API exposes a search "
                "endpoint that matches a keyword (case-insensitive substring) "
                "against victim names and victim website domains."
            ),
        },
    }

    opts = {
        "match_event_types": "DOMAIN_NAME,COMPANY_NAME",
        "cache_hours": 24,
        "min_seconds_between_calls": 65,
        "strict_domain_match": True,
    }

    optdescs = {
        "match_event_types": (
            "Comma-separated list of event types whose data should be queried "
            "against ransomware.live (e.g. 'DOMAIN_NAME,COMPANY_NAME,INTERNET_NAME')."
        ),
        "cache_hours": "Cache lookup results for this many hours to reduce API calls.",
        "min_seconds_between_calls": (
            "Minimum delay (seconds) between live API calls. The free API is rate-limited "
            "to 1 request per minute per endpoint; values below 65 may be rejected."
        ),
        "strict_domain_match": (
            "When the input event is a DOMAIN_NAME or INTERNET_NAME, only emit a hit if the "
            "returned victim record's 'domain' field also contains the queried value. "
            "Reduces false positives on common substrings."
        ),
    }

    # Class-level lock & timestamp so concurrent threads share the rate-limit state.
    _rate_lock = threading.Lock()
    _last_request_ts = 0.0

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self._mergeOpts(userOpts)

    def _watched_types(self):
        raw = self.opts.get("match_event_types") or ""
        types = [t.strip() for t in raw.split(",") if t.strip()]
        return types or ["DOMAIN_NAME", "COMPANY_NAME"]

    def watchedEvents(self):
        return self._watched_types()

    def producedEvents(self):
        return ["RANSOMWARE_VICTIM", "RAW_RIR_DATA"]

    def _query(self, keyword: str):
        """Query ransomware.live for a keyword. Returns parsed JSON or None."""
        keyword = keyword.strip()
        if not keyword:
            return None

        cache_label = "sfransomwarelive_" + keyword.lower()
        cached = self.sf.cacheGet(cache_label, self.opts["cache_hours"])
        if cached is not None:
            try:
                return json.loads(cached)
            except (ValueError, json.JSONDecodeError):
                self.debug(f"Discarding malformed cache entry for {keyword}")

        # Throttle to respect the 1-req/min/endpoint limit.
        with self._rate_lock:
            min_gap = float(self.opts.get("min_seconds_between_calls", 65) or 0)
            wait = min_gap - (time.time() - self._last_request_ts)
            if wait > 0:
                self.debug(f"Throttling ransomware.live call by {wait:.1f}s")
                time.sleep(wait)

            url = (
                "https://api.ransomware.live/v2/searchvictims/"
                + urllib.parse.quote(keyword, safe="")
            )
            self.debug(f"Querying ransomware.live: {url}")
            res = self.sf.fetchUrl(
                url,
                timeout=self.opts.get("_fetchtimeout", 30),
                useragent="SpiderFoot/sfp_ransomwarelive",
            )
            sfp_ransomwarelive._last_request_ts = time.time()

        if not res:
            return None
        code = res.get("code")
        content = res.get("content")
        if code == "429":
            self.error("ransomware.live rate-limited the request (HTTP 429).")
            return None
        if code != "200" or not content:
            self.debug(f"ransomware.live returned HTTP {code} for {keyword}")
            return None

        try:
            data = json.loads(content)
        except (ValueError, json.JSONDecodeError):
            self.error(f"ransomware.live returned non-JSON for {keyword}")
            return None

        # No-match responses are returned as {"error": "..."} — treat as empty list.
        if isinstance(data, dict) and "error" in data:
            data = []

        # Cache the normalised result (even an empty list — saves repeat queries).
        self.sf.cachePut(cache_label, json.dumps(data))
        return data

    def _victim_matches(self, event_name: str, query: str, victim: dict) -> bool:
        """Decide whether to keep a returned victim record for a given query."""
        if not self.opts.get("strict_domain_match", True):
            return True
        # Only apply strict matching to domain-shaped inputs; for COMPANY_NAME
        # the API's substring search against the victim name is already the
        # right signal and we don't want to over-filter.
        if event_name not in ("DOMAIN_NAME", "INTERNET_NAME", "AFFILIATE_DOMAIN_NAME"):
            return True
        q = (query or "").lower()
        d = (victim.get("domain") or "").lower()
        v = (victim.get("victim") or victim.get("post_title") or "").lower()
        return q and (q in d or q in v)

    def _format_descr(self, victim: dict, query: str) -> str:
        group = victim.get("group") or "unknown"
        attackdate = (victim.get("attackdate") or "").split("T")[0]
        country = victim.get("country") or "?"
        activity = victim.get("activity") or ""
        domain = victim.get("domain") or ""
        name = victim.get("victim") or victim.get("post_title") or ""
        description = (victim.get("description") or "").strip()
        if len(description) > 500:
            description = description[:500].rstrip() + "..."

        permalink = victim.get("permalink") or victim.get("claim_url") or ""

        lines = [
            f"Ransomware.live - Leak-Site Match for [{query}]",
            f" - Group: {group}",
        ]
        if name:
            lines.append(f" - Victim: {name}")
        if domain:
            lines.append(f" - Domain: {domain}")
        if attackdate:
            lines.append(f" - Attack Date: {attackdate}")
        if country and country != "?":
            lines.append(f" - Country: {country}")
        if activity:
            lines.append(f" - Sector: {activity}")
        if description:
            lines.append(f" - Description: {description}")
        if permalink:
            lines.append(f"<SFURL>{permalink}</SFURL>")
        return "\n".join(lines)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data
        srcModuleName = event.module

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName not in self._watched_types():
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return
        self.results[eventData] = True

        data = self._query(eventData)
        if not data:
            return

        kept = 0
        for victim in data:
            if not isinstance(victim, dict):
                continue
            if not self._victim_matches(eventName, eventData, victim):
                continue
            descr = self._format_descr(victim, eventData)
            evt = SpiderFootEvent("RANSOMWARE_VICTIM", descr, self.__name__, event)
            self.notifyListeners(evt)
            kept += 1

        if kept > 0:
            raw = SpiderFootEvent(
                "RAW_RIR_DATA",
                json.dumps(data)[:8000],
                self.__name__,
                event,
            )
            self.notifyListeners(raw)


# End of sfp_ransomwarelive class
