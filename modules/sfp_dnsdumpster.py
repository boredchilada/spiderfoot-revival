# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_dnsdumpster
# Purpose:     SpiderFoot plug-in for subdomain enumeration using
#              dnsdumpster.com
#
# Author:      TheTechromancer
#
# Created:     05/21/2021
# Copyright:   (c) Steve Micallef 2021
# Licence:     MIT
# -------------------------------------------------------------------------------

import re

from bs4 import BeautifulSoup

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_dnsdumpster(SpiderFootPlugin):

    meta = {
        "name": "DNSDumpster",
        "summary": "Passive subdomain enumeration using HackerTarget's DNSDumpster API.",
        "flags": ["apikey"],
        "useCases": ["Investigate", "Footprint", "Passive"],
        "categories": ["Passive DNS"],
        "dataSource": {
            "website": "https://dnsdumpster.com/",
            "model": "FREE_AUTH_LIMITED",
            "references": [
                "https://dnsdumpster.com/developer/",
            ],
            "apiKeyInstructions": [
                "Visit https://dnsdumpster.com/",
                "Create a free account",
                "The API key is available in your account settings",
                "Free accounts: 50 records/domain, 1 req per 2 seconds",
            ],
            "description": "DNSdumpster.com is a FREE domain research tool that can discover hosts related to a domain. "
            "As of 2025, DNSDumpster requires an API key for access. Free accounts are limited to 50 records per domain.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
    }

    # Option descriptions
    optdescs = {
        "api_key": "DNSDumpster API key. Required for access (free accounts available).",
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.debug("Setting up sfp_dnsdumpster")
        self.results = self.tempStorage()
        self.opts.update(userOpts)

    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME"]

    def producedEvents(self):
        return ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"]

    errorState = False

    def query(self, domain):
        ret = []

        if not self.opts.get("api_key"):
            self.error("You enabled sfp_dnsdumpster but did not set an API key! "
                       "DNSDumpster now requires an API key. Visit https://dnsdumpster.com/ to get one.")
            self.errorState = True
            return ret

        # Use the new JSON API (requires API key)
        import json
        import time

        url = f"https://api.dnsdumpster.com/domain/{domain}"
        headers = {
            "X-API-Key": self.opts["api_key"],
        }

        res = self.sf.fetchUrl(
            url,
            headers=headers,
            useragent=self.opts.get("_useragent", "SpiderFoot"),
            timeout=self.opts.get("_fetchtimeout", 30),
        )

        # Rate limit: 1 req per 2 seconds for free tier
        time.sleep(2)

        if not res or not res.get("content"):
            self.error("No response from DNSDumpster API")
            return ret

        if res["code"] == "401":
            self.error("DNSDumpster API key is invalid.")
            self.errorState = True
            return ret

        if res["code"] == "429":
            self.error("DNSDumpster API rate limit hit.")
            self.errorState = True
            return ret

        if res["code"] != "200":
            self.error(f"Bad response code \"{res['code']}\" from DNSDumpster API")
            return ret

        try:
            data = json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing DNSDumpster JSON response: {e}")
            return ret

        # Extract subdomains from the API response
        subdomains = set()
        for record in data.get("dns_records", {}).get("dns", []):
            host = record.get("host", "")
            if host and host.endswith(f".{domain}"):
                subdomains.add(host.lower())

        for record in data.get("dns_records", {}).get("mx", []):
            host = record.get("host", "")
            if host and host.endswith(f".{domain}"):
                subdomains.add(host.lower())

        for record in data.get("dns_records", {}).get("txt", []):
            host = record.get("host", "")
            if host and host.endswith(f".{domain}"):
                subdomains.add(host.lower())

        for record in data.get("dns_records", {}).get("host", []):
            host = record.get("host", "")
            if host and host.endswith(f".{domain}"):
                subdomains.add(host.lower())

        return list(subdomains)

    def sendEvent(self, source, host):
        if self.sf.resolveHost(host) or self.sf.resolveHost6(host):
            e = SpiderFootEvent("INTERNET_NAME", host, self.__name__, source)
        else:
            e = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, source)
        self.notifyListeners(e)

    def handleEvent(self, event):
        query = str(event.data).lower()

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        # skip if we've already processed this event (or its parent domain/subdomain)
        target = self.getTarget()
        eventDataHash = self.sf.hashstring(query)
        if eventDataHash in self.results or \
                (target.matches(query, includeParents=True) and not
                 target.matches(query, includeChildren=False)):
            self.debug(f"Skipping already-processed event, {event.eventType}, from {event.module}")
            return
        self.results[eventDataHash] = True

        for hostname in self.query(query):
            if target.matches(hostname, includeParents=True) and not \
                    target.matches(hostname, includeChildren=False):
                self.sendEvent(event, hostname)
            else:
                self.debug(f"Invalid subdomain: {hostname}")
