# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_zoomeye
# Purpose:      Query ZoomEye for internet-connected device and web application data.
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


class sfp_zoomeye(SpiderFootPlugin):

    meta = {
        "name": "ZoomEye",
        "summary": "Query ZoomEye for internet-connected devices, open ports, services, and web applications associated with the target.",
        "flags": ["apikey"],
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Search Engines"],
        "dataSource": {
            "website": "https://www.zoomeye.ai/",
            "model": "COMMERCIAL_ONLY",
            "references": [
                "https://www.zoomeye.ai/doc",
            ],
            "apiKeyInstructions": [
                "Visit https://www.zoomeye.ai/ and sign up",
                "Purchase a Personal plan ($19/mo minimum) for API access",
                "The API key is in your account profile",
            ],
            "favIcon": "https://www.zoomeye.ai/favicon.ico",
            "logo": "https://www.zoomeye.ai/logo.png",
            "description": "ZoomEye is a cyberspace search engine by Knownsec that indexes "
            "internet-connected devices and web applications. It provides host, port, service, "
            "banner, and SSL certificate data. API access requires a paid plan.",
        },
    }

    opts = {
        "api_key": "",
        "max_pages": 3,
        "request_delay": 1.0,
    }

    optdescs = {
        "api_key": "ZoomEye API key.",
        "max_pages": "Maximum number of search result pages to retrieve.",
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
            "TCP_PORT_OPEN",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "OPERATING_SYSTEM",
            "WEBSERVER_BANNER",
            "RAW_RIR_DATA",
        ]

    def queryHost(self, query, page=1):
        """Query ZoomEye host search."""
        url = f"https://api.zoomeye.org/host/search?query={query}&page={page}"

        headers = {"API-KEY": self.opts["api_key"]}

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
            headers=headers,
        )

        time.sleep(self.opts["request_delay"])

        if not res or not res.get("content"):
            return None

        if res["code"] in ["401", "403"]:
            self.error("ZoomEye API key is invalid or quota exhausted.")
            self.errorState = True
            return None

        if res["code"] == "429":
            self.error("ZoomEye rate limit hit.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from ZoomEye")
            return None

        try:
            return json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing ZoomEye response: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if not self.opts["api_key"]:
            self.error("You enabled sfp_zoomeye but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "IP_ADDRESS":
            query = f"ip:{eventData}"
        else:
            query = f"hostname:{eventData}"

        for page in range(1, self.opts["max_pages"] + 1):
            if self.checkForStop():
                return

            data = self.queryHost(query, page)
            if not data:
                break

            matches = data.get("matches", [])
            if not matches:
                break

            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
            self.notifyListeners(e)

            for match in matches:
                ip = match.get("ip", "")
                portinfo = match.get("portinfo", {})
                port = portinfo.get("port", "")

                if ip and port:
                    port_str = f"{ip}:{port}"
                    if port_str not in self.results:
                        self.results[port_str] = True
                        e = SpiderFootEvent("TCP_PORT_OPEN", port_str, self.__name__, event)
                        self.notifyListeners(e)

                hostname = portinfo.get("hostname", "")
                if hostname and hostname not in self.results:
                    self.results[hostname] = True
                    if self.getTarget().matches(hostname):
                        e = SpiderFootEvent("INTERNET_NAME", hostname, self.__name__, event)
                    else:
                        e = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", hostname, self.__name__, event)
                    self.notifyListeners(e)

                os_name = portinfo.get("os", "")
                if os_name:
                    e = SpiderFootEvent("OPERATING_SYSTEM", os_name, self.__name__, event)
                    self.notifyListeners(e)

                banner = portinfo.get("banner", "")
                if banner and len(banner) < 500:
                    e = SpiderFootEvent("WEBSERVER_BANNER", banner, self.__name__, event)
                    self.notifyListeners(e)


# End of sfp_zoomeye class
