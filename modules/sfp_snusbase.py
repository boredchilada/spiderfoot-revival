# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_snusbase
# Purpose:      Query Snusbase for breach/credential data.
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


class sfp_snusbase(SpiderFootPlugin):

    meta = {
        "name": "Snusbase",
        "summary": "Query Snusbase for breached credentials associated with email addresses, usernames, and domains.",
        "flags": ["apikey"],
        "useCases": ["Investigate", "Passive"],
        "categories": ["Leaks, Dumps and Breaches"],
        "dataSource": {
            "website": "https://snusbase.com/",
            "model": "COMMERCIAL_ONLY",
            "references": [
                "https://docs.snusbase.com/",
            ],
            "apiKeyInstructions": [
                "Visit https://snusbase.com/ and purchase a membership",
                "The activation code (API key) is provided with your membership",
            ],
            "favIcon": "https://snusbase.com/favicon.ico",
            "logo": "https://snusbase.com/logo.png",
            "description": "Snusbase is a breach data search engine that provides access to "
            "compromised emails, usernames, passwords, password hashes, names, and IP addresses. "
            "API access requires a paid membership.",
        },
    }

    opts = {
        "api_key": "",
        "request_delay": 1.0,
    }

    optdescs = {
        "api_key": "Snusbase activation code (API key).",
        "request_delay": "Delay between API requests in seconds.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["EMAILADDR", "DOMAIN_NAME", "USERNAME"]

    def producedEvents(self):
        return [
            "LEAKSITE_CONTENT",
            "EMAILADDR_COMPROMISED",
            "RAW_RIR_DATA",
        ]

    def querySnusbase(self, term, search_type="email"):
        """Query the Snusbase search API."""
        url = "https://api.snusbase.com/data/search"

        headers = {
            "Auth": self.opts["api_key"],
            "Content-Type": "application/json",
        }

        payload = json.dumps({
            "terms": [term],
            "types": [search_type],
            "wildcard": False,
        })

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
            headers=headers,
            postData=payload,
        )

        time.sleep(self.opts["request_delay"])

        if not res or not res.get("content"):
            return None

        if res["code"] in ["401", "403"]:
            self.error("Snusbase API key is invalid or membership expired.")
            self.errorState = True
            return None

        if res["code"] == "429":
            self.error("Snusbase rate limit hit.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from Snusbase")
            return None

        try:
            data = json.loads(res["content"])
            if "errors" in data:
                self.error(f"Snusbase error: {data['errors']}")
                return None
            return data
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing Snusbase response: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if not self.opts["api_key"]:
            self.error("You enabled sfp_snusbase but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "EMAILADDR":
            search_type = "email"
        elif eventName == "DOMAIN_NAME":
            search_type = "_domain"
        elif eventName == "USERNAME":
            search_type = "username"
        else:
            return

        data = self.querySnusbase(eventData, search_type)
        if not data:
            return

        result_size = data.get("size", 0)
        if result_size == 0:
            return

        e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
        self.notifyListeners(e)

        if eventName == "EMAILADDR":
            e = SpiderFootEvent(
                "EMAILADDR_COMPROMISED",
                f"{eventData} [Snusbase - {result_size} breach records]",
                self.__name__,
                event,
            )
            self.notifyListeners(e)

        # Process results grouped by breach source
        results = data.get("results", {})
        for source_name, records in results.items():
            breach_count = len(records) if isinstance(records, list) else 0

            descr = f"Snusbase - Breach Data Found [{eventData}]\n"
            descr += f" - Source: {source_name}\n"
            descr += f" - Records: {breach_count}\n"
            descr += "<SFURL>https://snusbase.com/</SFURL>"

            e = SpiderFootEvent("LEAKSITE_CONTENT", descr, self.__name__, event)
            self.notifyListeners(e)


# End of sfp_snusbase class
