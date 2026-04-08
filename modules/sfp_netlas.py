# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_netlas
# Purpose:      Query Netlas.io for attack surface, DNS, WHOIS, and certificate data.
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


class sfp_netlas(SpiderFootPlugin):

    meta = {
        "name": "Netlas.io",
        "summary": "Query Netlas.io for internet scan data, DNS records, WHOIS, and SSL certificates related to the target.",
        "flags": ["apikey"],
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Search Engines"],
        "dataSource": {
            "website": "https://netlas.io/",
            "model": "FREE_AUTH_LIMITED",
            "references": [
                "https://docs.netlas.io/",
                "https://docs.netlas.io/api-reference/",
            ],
            "apiKeyInstructions": [
                "Visit https://app.netlas.io/ and sign up for a free account",
                "Navigate to your profile settings",
                "Copy the API key from the dashboard",
            ],
            "favIcon": "https://app.netlas.io/favicon.ico",
            "logo": "https://netlas.io/logo.png",
            "description": "Netlas.io is an internet intelligence search engine providing "
            "attack surface discovery, DNS records, WHOIS data, SSL certificate search, "
            "and vulnerability detection. The free Community plan includes 50 requests/day.",
        },
    }

    opts = {
        "api_key": "",
        "request_delay": 1.0,
    }

    optdescs = {
        "api_key": "Netlas.io API key.",
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
        return ["DOMAIN_NAME", "INTERNET_NAME", "IP_ADDRESS"]

    def producedEvents(self):
        return [
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "IP_ADDRESS",
            "TCP_PORT_OPEN",
            "WEBSERVER_BANNER",
            "WEBSERVER_TECHNOLOGY",
            "RAW_RIR_DATA",
        ]

    def queryHost(self, host):
        """Query the Netlas host summary endpoint."""
        url = f"https://app.netlas.io/api/host/{host}/"

        headers = {"Authorization": f"Bearer {self.opts['api_key']}"}

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
            headers=headers,
        )

        time.sleep(self.opts["request_delay"])
        return self._parseResponse(res)

    def queryDomains(self, domain):
        """Query the Netlas domains endpoint for subdomains."""
        url = f"https://app.netlas.io/api/domains/?q=domain:*.{domain}&source_type=include&start=0&indices="

        headers = {"Authorization": f"Bearer {self.opts['api_key']}"}

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
            headers=headers,
        )

        time.sleep(self.opts["request_delay"])
        return self._parseResponse(res)

    def queryResponses(self, query):
        """Query the Netlas responses (scan data) endpoint."""
        url = f"https://app.netlas.io/api/responses/?q={query}&start=0&indices="

        headers = {"Authorization": f"Bearer {self.opts['api_key']}"}

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
            headers=headers,
        )

        time.sleep(self.opts["request_delay"])
        return self._parseResponse(res)

    def _parseResponse(self, res):
        if not res or not res.get("content"):
            return None

        if res["code"] == "401":
            self.error("Netlas API key is invalid.")
            self.errorState = True
            return None

        if res["code"] == "429":
            self.error("Netlas API rate/quota limit reached.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from Netlas")
            return None

        try:
            return json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing Netlas response: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if not self.opts["api_key"]:
            self.error("You enabled sfp_netlas but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "IP_ADDRESS":
            # Query host summary for IP
            data = self.queryHost(eventData)
            if data:
                e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
                self.notifyListeners(e)

            # Query scan data for IP
            data = self.queryResponses(f"host:{eventData}")
            if data:
                for item in data.get("items", []):
                    src = item.get("data", {})

                    port = src.get("port")
                    if port:
                        e = SpiderFootEvent("TCP_PORT_OPEN", f"{eventData}:{port}", self.__name__, event)
                        self.notifyListeners(e)

                    banner = src.get("http", {}).get("headers", {}).get("server", "")
                    if banner:
                        e = SpiderFootEvent("WEBSERVER_BANNER", banner, self.__name__, event)
                        self.notifyListeners(e)

        elif eventName in ["DOMAIN_NAME", "INTERNET_NAME"]:
            # Query subdomains
            data = self.queryDomains(eventData)
            if data:
                e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
                self.notifyListeners(e)

                for item in data.get("items", []):
                    src = item.get("data", {})
                    domain = src.get("domain", "")
                    if domain and domain != eventData:
                        if domain not in self.results:
                            self.results[domain] = True
                            if self.getTarget().matches(domain):
                                e = SpiderFootEvent("INTERNET_NAME", domain, self.__name__, event)
                            else:
                                e = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", domain, self.__name__, event)
                            self.notifyListeners(e)

                    # A records → IP addresses
                    for a_rec in src.get("a", []):
                        if a_rec not in self.results:
                            self.results[a_rec] = True
                            e = SpiderFootEvent("IP_ADDRESS", a_rec, self.__name__, event)
                            self.notifyListeners(e)


# End of sfp_netlas class
