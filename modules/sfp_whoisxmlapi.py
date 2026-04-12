# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_whoisxmlapi
# Purpose:      Query WhoisXML API for WHOIS, DNS, reverse IP, and subdomain data.
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


class sfp_whoisxmlapi(SpiderFootPlugin):

    meta = {
        "name": "WhoisXML API",
        "summary": "Query WhoisXML API for WHOIS records, DNS lookups, reverse IP, and subdomain discovery.",
        "flags": ["apikey"],
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Search Engines"],
        "dataSource": {
            "website": "https://www.whoisxmlapi.com/",
            "model": "FREE_AUTH_LIMITED",
            "references": [
                "https://docs.whoisxmlapi.com/",
            ],
            "apiKeyInstructions": [
                "Visit https://www.whoisxmlapi.com/ and sign up for a free account",
                "500 free credits are included on signup",
                "The API key is available in your account dashboard",
            ],
            "favIcon": "https://www.whoisxmlapi.com/favicon.ico",
            "logo": "https://www.whoisxmlapi.com/logo.png",
            "description": "WhoisXML API provides comprehensive WHOIS, DNS, reverse IP, "
            "subdomain discovery, IP geolocation, and domain reputation data. "
            "500 free API credits are included with account signup.",
        },
    }

    opts = {
        "api_key": "",
        "request_delay": 1.0,
    }

    optdescs = {
        "api_key": "WhoisXML API key.",
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
            "DOMAIN_WHOIS",
            "DOMAIN_REGISTRAR",
            "RAW_RIR_DATA",
        ]

    def querySubdomains(self, domain):
        """Query the Subdomains Lookup API."""
        url = f"https://subdomains.whoisxmlapi.com/api/v1?apiKey={self.opts['api_key']}&domainName={domain}&outputFormat=JSON"

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
        )

        time.sleep(self.opts["request_delay"])
        return self._parseResponse(res)

    def queryWhois(self, domain):
        """Query the WHOIS API."""
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={self.opts['api_key']}&domainName={domain}&outputFormat=JSON"

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
        )

        time.sleep(self.opts["request_delay"])
        return self._parseResponse(res)

    def queryReverseIP(self, ip):
        """Query the Reverse IP API."""
        url = f"https://reverse-ip.whoisxmlapi.com/api/v1?apiKey={self.opts['api_key']}&ip={ip}&outputFormat=JSON"

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
        )

        time.sleep(self.opts["request_delay"])
        return self._parseResponse(res)

    def _parseResponse(self, res):
        if not res or not res.get("content"):
            return None

        if res["code"] == "401":
            self.error("WhoisXML API key is invalid.")
            self.errorState = True
            return None

        if res["code"] == "429":
            self.error("WhoisXML API rate limit reached.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from WhoisXML API")
            return None

        try:
            return json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing WhoisXML API response: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if not self.opts["api_key"]:
            self.error("You enabled sfp_whoisxmlapi but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName in ["DOMAIN_NAME", "INTERNET_NAME"]:
            # Subdomain lookup
            data = self.querySubdomains(eventData)
            if data:
                e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
                self.notifyListeners(e)

                result = data.get("result", {})
                records = result.get("records", [])
                for rec in records:
                    subdomain = rec.get("domain", "")
                    if subdomain and subdomain != eventData and subdomain not in self.results:
                        self.results[subdomain] = True
                        if self.getTarget().matches(subdomain):
                            e = SpiderFootEvent("INTERNET_NAME", subdomain, self.__name__, event)
                        else:
                            e = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", subdomain, self.__name__, event)
                        self.notifyListeners(e)

            # WHOIS lookup (only for DOMAIN_NAME to avoid excessive queries)
            if eventName == "DOMAIN_NAME":
                data = self.queryWhois(eventData)
                if data:
                    whois_record = data.get("WhoisRecord", {})
                    raw_text = whois_record.get("rawText", "")
                    if raw_text:
                        e = SpiderFootEvent("DOMAIN_WHOIS", raw_text, self.__name__, event)
                        self.notifyListeners(e)

                    registrar = whois_record.get("registrarName", "")
                    if registrar:
                        e = SpiderFootEvent("DOMAIN_REGISTRAR", registrar, self.__name__, event)
                        self.notifyListeners(e)

        elif eventName == "IP_ADDRESS":
            data = self.queryReverseIP(eventData)
            if data:
                e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
                self.notifyListeners(e)

                result = data.get("result", [])
                for rec in result:
                    hostname = rec.get("name", "")
                    if hostname and hostname not in self.results:
                        self.results[hostname] = True
                        if self.getTarget().matches(hostname):
                            e = SpiderFootEvent("INTERNET_NAME", hostname, self.__name__, event)
                        else:
                            e = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", hostname, self.__name__, event)
                        self.notifyListeners(e)


# End of sfp_whoisxmlapi class
