# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_bevigil
# Purpose:      Query BeVigil for mobile app OSINT data (subdomains, S3 buckets,
#               URLs extracted from Android APKs).
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


class sfp_bevigil(SpiderFootPlugin):

    meta = {
        "name": "BeVigil",
        "summary": "Query BeVigil's OSINT API for subdomains, URLs, and S3 buckets extracted from mobile application analysis.",
        "flags": ["apikey"],
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Search Engines"],
        "dataSource": {
            "website": "https://bevigil.com/",
            "model": "FREE_AUTH_LIMITED",
            "references": [
                "https://osint.bevigil.com/docs",
                "https://bevigil.com/osint-api",
            ],
            "apiKeyInstructions": [
                "Visit https://bevigil.com/ and sign up for a free account",
                "Navigate to https://bevigil.com/osint/api-keys",
                "Copy your API key (25 free credits with personal email)",
            ],
            "favIcon": "https://bevigil.com/favicon.ico",
            "logo": "https://bevigil.com/logo.png",
            "description": "BeVigil provides OSINT data derived from static analysis of 2M+ "
            "Android mobile applications. It discovers subdomains, URLs, S3 buckets, "
            "Firebase databases, and API endpoints hardcoded in mobile apps.",
        },
    }

    opts = {
        "api_key": "",
        "request_delay": 1.0,
    }

    optdescs = {
        "api_key": "BeVigil OSINT API key.",
        "request_delay": "Delay between API requests in seconds.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME"]

    def producedEvents(self):
        return [
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "CLOUD_STORAGE_BUCKET_OPEN",
            "LINKED_URL_INTERNAL",
            "RAW_RIR_DATA",
        ]

    def _query(self, endpoint, domain):
        url = f"https://osint.bevigil.com/api/{domain}/{endpoint}/"

        headers = {"X-Access-Token": self.opts["api_key"]}

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
            self.error("BeVigil API key is invalid.")
            self.errorState = True
            return None

        if res["code"] == "429":
            self.error("BeVigil API rate/credit limit reached.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from BeVigil")
            return None

        try:
            return json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing BeVigil response: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if not self.opts["api_key"]:
            self.error("You enabled sfp_bevigil but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        # Subdomains
        data = self._query("subdomains", eventData)
        if data:
            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
            self.notifyListeners(e)

            for subdomain in data.get("subdomains", []):
                if subdomain and subdomain != eventData and subdomain not in self.results:
                    self.results[subdomain] = True
                    if self.getTarget().matches(subdomain):
                        e = SpiderFootEvent("INTERNET_NAME", subdomain, self.__name__, event)
                    else:
                        e = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", subdomain, self.__name__, event)
                    self.notifyListeners(e)

        if self.checkForStop():
            return

        # S3 Buckets
        data = self._query("s3-buckets", eventData)
        if data:
            for bucket in data.get("s3_buckets", []):
                if bucket and bucket not in self.results:
                    self.results[bucket] = True
                    e = SpiderFootEvent("CLOUD_STORAGE_BUCKET_OPEN", bucket, self.__name__, event)
                    self.notifyListeners(e)

        if self.checkForStop():
            return

        # URLs
        data = self._query("urls", eventData)
        if data:
            for url in data.get("urls", []):
                if url and url not in self.results:
                    self.results[url] = True
                    e = SpiderFootEvent("LINKED_URL_INTERNAL", url, self.__name__, event)
                    self.notifyListeners(e)


# End of sfp_bevigil class
