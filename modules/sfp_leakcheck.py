# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_leakcheck
# Purpose:      Query LeakCheck for breach data on email addresses and usernames.
#
# Author:       SpiderFoot Revival Project
#
# Created:      2026-04-08
# Copyright:    (c) SpiderFoot Revival Project
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_leakcheck(SpiderFootPlugin):

    meta = {
        "name": "LeakCheck",
        "summary": "Query LeakCheck's breach database for exposed credentials associated with email addresses and usernames.",
        "flags": [],
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Leaks, Dumps and Breaches"],
        "dataSource": {
            "website": "https://leakcheck.io/",
            "model": "FREE_NOAUTH_LIMITED",
            "references": [
                "https://wiki.leakcheck.io/en/api",
                "https://wiki.leakcheck.io/en/api/public",
                "https://wiki.leakcheck.io/en/api/api-v2-pro",
            ],
            "apiKeyInstructions": [
                "The public API works without an API key (limited data).",
                "For full data, visit https://leakcheck.io/ and purchase a plan.",
                "Navigate to your account settings to find your API key.",
            ],
            "favIcon": "https://leakcheck.io/favicon.ico",
            "logo": "https://leakcheck.io/img/logo.png",
            "description": "LeakCheck is a data breach search engine with 7.5B+ entries. "
            "The free public API returns breach source names and exposed field types. "
            "The Pro API (paid) returns full breach details including passwords.",
        },
    }

    opts = {
        "api_key": "",
        "request_delay": 1.0,
    }

    optdescs = {
        "api_key": "LeakCheck Pro API key (optional — public API works without a key but returns limited data).",
        "request_delay": "Delay between API requests in seconds (public API limit: 1 req/s).",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["EMAILADDR", "USERNAME"]

    def producedEvents(self):
        return [
            "LEAKSITE_CONTENT",
            "LEAKSITE_URL",
            "RAW_RIR_DATA",
        ]

    def queryPublicAPI(self, qry):
        """Query the free public API (no key needed)."""
        url = f"https://leakcheck.io/api/public?check={qry}"

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
        )

        time.sleep(self.opts["request_delay"])

        if not res or not res.get("content"):
            return None

        if res["code"] == "429":
            self.error("LeakCheck rate limit hit. Increase request_delay.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from LeakCheck public API")
            return None

        try:
            return json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing LeakCheck response: {e}")
            return None

    def queryProAPI(self, qry):
        """Query the Pro API v2 (requires key)."""
        url = f"https://leakcheck.io/api/v2/query/{qry}"

        headers = {"X-API-Key": self.opts["api_key"]}

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
            headers=headers,
        )

        time.sleep(self.opts["request_delay"])

        if not res or not res.get("content"):
            return None

        if res["code"] == "401":
            self.error("LeakCheck API key is invalid.")
            self.errorState = True
            return None

        if res["code"] == "403":
            self.error("LeakCheck API: plan limit reached or inactive.")
            self.errorState = True
            return None

        if res["code"] == "429":
            self.error("LeakCheck rate limit hit.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from LeakCheck Pro API")
            return None

        try:
            return json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing LeakCheck response: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        # Use Pro API if key is set, otherwise public API
        if self.opts["api_key"]:
            data = self.queryProAPI(eventData)
        else:
            data = self.queryPublicAPI(eventData)

        if not data:
            return

        if not data.get("success", False):
            self.debug(f"LeakCheck returned no results for {eventData}")
            return

        found = data.get("found", 0)
        if found == 0:
            return

        e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
        self.notifyListeners(e)

        # Pro API returns 'result' array
        if "result" in data:
            for rec in data["result"]:
                source = rec.get("source", {})
                source_name = source.get("name", "Unknown")
                breach_date = source.get("breach_date", "Unknown")
                fields = rec.get("fields", [])

                descr = f"LeakCheck - Breach Detected for [{eventData}]\n"
                descr += f" - Source: {source_name}\n"
                descr += f" - Breach Date: {breach_date}\n"
                descr += f" - Exposed Fields: {', '.join(fields)}\n"
                descr += f"<SFURL>https://leakcheck.io/</SFURL>"

                e = SpiderFootEvent("LEAKSITE_CONTENT", descr, self.__name__, event)
                self.notifyListeners(e)

        # Public API returns 'sources' array
        elif "sources" in data:
            for source in data["sources"]:
                source_name = source.get("name", "Unknown")
                breach_date = source.get("date", "Unknown")

                descr = f"LeakCheck - Breach Detected for [{eventData}]\n"
                descr += f" - Source: {source_name}\n"
                descr += f" - Breach Date: {breach_date}\n"
                if "fields" in data:
                    descr += f" - Exposed Fields: {', '.join(data['fields'])}\n"
                descr += f"<SFURL>https://leakcheck.io/</SFURL>"

                e = SpiderFootEvent("LEAKSITE_CONTENT", descr, self.__name__, event)
                self.notifyListeners(e)


# End of sfp_leakcheck class
