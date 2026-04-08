# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_opensanctions
# Purpose:      Query OpenSanctions for sanctions/PEP screening.
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


class sfp_opensanctions(SpiderFootPlugin):

    meta = {
        "name": "OpenSanctions",
        "summary": "Screen person and company names against international sanctions lists and Politically Exposed Persons (PEP) databases.",
        "flags": ["apikey"],
        "useCases": ["Investigate", "Passive"],
        "categories": ["Public Registries"],
        "dataSource": {
            "website": "https://www.opensanctions.org/",
            "model": "FREE_AUTH_LIMITED",
            "references": [
                "https://www.opensanctions.org/docs/api/",
                "https://api.opensanctions.org/openapi.json",
            ],
            "apiKeyInstructions": [
                "Visit https://www.opensanctions.org/api/",
                "Sign up for a free API key (non-commercial) or paid key",
                "API keys are emailed to you after registration",
            ],
            "favIcon": "https://www.opensanctions.org/favicon.ico",
            "logo": "https://www.opensanctions.org/static/logo.png",
            "description": "OpenSanctions aggregates sanctions lists, lists of politically exposed "
            "persons (PEPs), and related entities from multiple governments and international "
            "organizations. The API supports fuzzy matching of names against these lists.",
        },
    }

    opts = {
        "api_key": "",
        "min_score": 0.7,
        "request_delay": 1.0,
    }

    optdescs = {
        "api_key": "OpenSanctions API key.",
        "min_score": "Minimum match score (0.0 to 1.0) for reporting results. Default 0.7.",
        "request_delay": "Delay between API requests in seconds.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["HUMAN_NAME", "COMPANY_NAME"]

    def producedEvents(self):
        return [
            "RAW_RIR_DATA",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
        ]

    def queryMatch(self, name, schema="Thing"):
        """Query the OpenSanctions match endpoint."""
        url = "https://api.opensanctions.org/match/default"

        headers = {
            "Authorization": f"ApiKey {self.opts['api_key']}",
            "Content-Type": "application/json",
        }

        payload = json.dumps({
            "queries": {
                "q1": {
                    "schema": schema,
                    "properties": {
                        "name": [name],
                    },
                }
            }
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

        if res["code"] == "401":
            self.error("OpenSanctions API key is invalid.")
            self.errorState = True
            return None

        if res["code"] == "429":
            self.error("OpenSanctions API rate limit hit.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from OpenSanctions")
            return None

        try:
            return json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing OpenSanctions response: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if not self.opts["api_key"]:
            self.error("You enabled sfp_opensanctions but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        schema = "Person" if eventName == "HUMAN_NAME" else "Organization"
        data = self.queryMatch(eventData, schema)

        if not data:
            return

        responses = data.get("responses", {}).get("q1", {})
        results = responses.get("results", [])

        if not results:
            return

        e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
        self.notifyListeners(e)

        for result in results:
            score = result.get("score", 0)
            if score < self.opts["min_score"]:
                continue

            name = result.get("caption", "Unknown")
            datasets = [d.get("name", d.get("label", "")) for d in result.get("datasets", [])]
            properties = result.get("properties", {})
            countries = properties.get("country", [])

            descr = f"OpenSanctions - Sanctions/PEP Match [{eventData}]\n"
            descr += f" - Matched: {name} (score: {score:.2f})\n"
            descr += f" - Datasets: {', '.join(datasets)}\n"
            if countries:
                descr += f" - Countries: {', '.join(countries)}\n"
            descr += f"<SFURL>https://www.opensanctions.org/entities/{result.get('id', '')}/</SFURL>"

            e = SpiderFootEvent("MALICIOUS_AFFILIATE_INTERNET_NAME", descr, self.__name__, event)
            self.notifyListeners(e)


# End of sfp_opensanctions class
