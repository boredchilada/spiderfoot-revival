# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_fofa
# Purpose:      Query FOFA for internet asset intelligence.
#
# Author:       SpiderFoot Revival Project
#
# Created:      2026-04-08
# Copyright:    (c) SpiderFoot Revival Project
# Licence:      MIT
# -------------------------------------------------------------------------------

import base64
import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_fofa(SpiderFootPlugin):

    meta = {
        "name": "FOFA",
        "summary": "Query FOFA for internet asset data including IPs, ports, services, and technologies associated with the target.",
        "flags": ["apikey"],
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Search Engines"],
        "dataSource": {
            "website": "https://en.fofa.info/",
            "model": "COMMERCIAL_ONLY",
            "references": [
                "https://en.fofa.info/api",
            ],
            "apiKeyInstructions": [
                "Visit https://en.fofa.info/ and sign up",
                "Purchase a Professional plan ($119/mo annual minimum) for API access",
                "Find your API key and email in account settings",
            ],
            "favIcon": "https://en.fofa.info/favicon.ico",
            "logo": "https://en.fofa.info/logo.png",
            "description": "FOFA is a Chinese internet asset search engine that indexes publicly "
            "accessible network assets worldwide. It provides IP, port, service, banner, "
            "certificate, and technology data. API access requires a Professional plan or above.",
        },
    }

    opts = {
        "api_key": "",
        "api_email": "",
        "max_pages": 3,
        "request_delay": 1.0,
    }

    optdescs = {
        "api_key": "FOFA API key.",
        "api_email": "FOFA account email address (required for API auth).",
        "max_pages": "Maximum number of search result pages to retrieve.",
        "request_delay": "Delay between API requests in seconds (FOFA rate limit: 1 req/s).",
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
            "RAW_RIR_DATA",
        ]

    def queryFOFA(self, query, page=1, size=100):
        """Query the FOFA search API."""
        qbase64 = base64.b64encode(query.encode("utf-8")).decode("utf-8")
        fields = "domain,host,ip,port,title,server,country,city"

        url = (
            f"https://api.fofa.info/v1/search/all"
            f"?email={self.opts['api_email']}"
            f"&key={self.opts['api_key']}"
            f"&qbase64={qbase64}"
            f"&fields={fields}"
            f"&page={page}"
            f"&size={size}"
        )

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
        )

        time.sleep(self.opts["request_delay"])

        if not res or not res.get("content"):
            return None

        if res["code"] in ["401", "403"]:
            self.error("FOFA API authentication failed. Check email and key.")
            self.errorState = True
            return None

        if res["code"] == "429":
            self.error("FOFA API rate limit hit.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from FOFA")
            return None

        try:
            data = json.loads(res["content"])
            if data.get("error", False):
                self.error(f"FOFA API error: {data.get('errmsg', 'unknown')}")
                return None
            return data
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing FOFA response: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if not self.opts["api_key"] or not self.opts["api_email"]:
            self.error("You enabled sfp_fofa but did not set an API key and email!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "IP_ADDRESS":
            query = f'ip="{eventData}"'
        else:
            query = f'domain="{eventData}"'

        for page in range(1, self.opts["max_pages"] + 1):
            if self.checkForStop():
                return

            data = self.queryFOFA(query, page)
            if not data:
                break

            results = data.get("results", [])
            if not results:
                break

            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
            self.notifyListeners(e)

            # Results are arrays: [domain, host, ip, port, title, server, country, city]
            for row in results:
                if len(row) < 6:
                    continue

                domain, host, ip, port, title, server = row[0], row[1], row[2], row[3], row[4], row[5]

                # IP + port
                if ip and port:
                    port_str = f"{ip}:{port}"
                    if port_str not in self.results:
                        self.results[port_str] = True
                        e = SpiderFootEvent("TCP_PORT_OPEN", port_str, self.__name__, event)
                        self.notifyListeners(e)

                # IP addresses
                if ip and ip not in self.results:
                    self.results[ip] = True
                    e = SpiderFootEvent("IP_ADDRESS", ip, self.__name__, event)
                    self.notifyListeners(e)

                # Hostnames
                if domain and domain not in self.results:
                    self.results[domain] = True
                    if self.getTarget().matches(domain):
                        e = SpiderFootEvent("INTERNET_NAME", domain, self.__name__, event)
                    else:
                        e = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", domain, self.__name__, event)
                    self.notifyListeners(e)

                # Server banner (deduplicated)
                if server and server not in self.results:
                    self.results[server] = True
                    e = SpiderFootEvent("WEBSERVER_BANNER", server, self.__name__, event)
                    self.notifyListeners(e)


# End of sfp_fofa class
