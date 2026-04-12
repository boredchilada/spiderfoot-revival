# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_validin
# Purpose:      Query Validin for DNS history and subdomain intelligence.
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


class sfp_validin(SpiderFootPlugin):

    meta = {
        "name": "Validin",
        "summary": "Query Validin for current and historical DNS records, subdomain enumeration, and certificate transparency data.",
        "flags": ["apikey"],
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Passive DNS"],
        "dataSource": {
            "website": "https://www.validin.com/",
            "model": "FREE_AUTH_LIMITED",
            "references": [
                "https://docs.validin.com/",
            ],
            "apiKeyInstructions": [
                "Visit https://app.validin.com/ and sign up for a free account",
                "Navigate to your account settings",
                "Copy your API key from the dashboard",
            ],
            "favIcon": "https://app.validin.com/favicon.ico",
            "logo": "https://www.validin.com/logo.png",
            "description": "Validin provides DNS intelligence with 4+ years of historical data, "
            "subdomain enumeration, certificate transparency log search, and OSINT aggregation "
            "from 650+ sources. The free Community plan includes 10 queries/day and 50/month.",
        },
    }

    opts = {
        "api_key": "",
        "request_delay": 1.0,
    }

    optdescs = {
        "api_key": "Validin API key.",
        "request_delay": "Delay between API requests in seconds.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME", "IP_ADDRESS"]

    def producedEvents(self):
        return [
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "IP_ADDRESS",
            "RAW_RIR_DATA",
        ]

    def queryDomain(self, domain):
        """Query Validin for subdomains and DNS history of a domain."""
        url = f"https://app.validin.com/api/axon/domain/dns/history?domain={domain}"

        headers = {"Authorization": f"BEARER {self.opts['api_key']}"}

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
            headers=headers,
        )

        time.sleep(self.opts["request_delay"])
        return self._parseResponse(res)

    def queryIP(self, ip):
        """Query Validin for DNS history of an IP address."""
        url = f"https://app.validin.com/api/axon/ip/dns/history?ip={ip}"

        headers = {"Authorization": f"BEARER {self.opts['api_key']}"}

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
            self.error("Validin API key is invalid.")
            self.errorState = True
            return None

        if res["code"] == "429":
            self.error("Validin API quota/rate limit reached.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from Validin")
            return None

        try:
            return json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing Validin response: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if not self.opts["api_key"]:
            self.error("You enabled sfp_validin but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName in ["DOMAIN_NAME", "INTERNET_NAME"]:
            data = self.queryDomain(eventData)
            if not data:
                return

            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
            self.notifyListeners(e)

            # Extract subdomains from DNS records
            records = data.get("records", [])
            for rec in records:
                hostname = rec.get("hostname", "")
                if hostname and hostname != eventData and hostname not in self.results:
                    self.results[hostname] = True
                    if self.getTarget().matches(hostname):
                        e = SpiderFootEvent("INTERNET_NAME", hostname, self.__name__, event)
                    else:
                        e = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", hostname, self.__name__, event)
                    self.notifyListeners(e)

                # Extract IPs from A records
                for value in rec.get("values", []):
                    if self.sf.validIP(value) and value not in self.results:
                        self.results[value] = True
                        e = SpiderFootEvent("IP_ADDRESS", value, self.__name__, event)
                        self.notifyListeners(e)

        elif eventName == "IP_ADDRESS":
            data = self.queryIP(eventData)
            if not data:
                return

            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
            self.notifyListeners(e)

            # Extract hostnames from reverse DNS
            records = data.get("records", [])
            for rec in records:
                hostname = rec.get("hostname", "")
                if hostname and hostname not in self.results:
                    self.results[hostname] = True
                    if self.getTarget().matches(hostname):
                        e = SpiderFootEvent("INTERNET_NAME", hostname, self.__name__, event)
                    else:
                        e = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", hostname, self.__name__, event)
                    self.notifyListeners(e)


# End of sfp_validin class
