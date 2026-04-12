# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_hudsonrock
# Purpose:      Query Hudson Rock's free Cavalier OSINT API for infostealer
#               breach intelligence.
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


class sfp_hudsonrock(SpiderFootPlugin):

    meta = {
        "name": "Hudson Rock",
        "summary": "Query Hudson Rock's Cavalier API for infostealer malware exposure on email addresses and domains.",
        "flags": [],
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Leaks, Dumps and Breaches"],
        "dataSource": {
            "website": "https://www.hudsonrock.com/",
            "model": "FREE_NOAUTH_LIMITED",
            "references": [
                "https://docs.hudsonrock.com/",
                "https://cavalier.hudsonrock.com/docs",
            ],
            "favIcon": "https://www.hudsonrock.com/favicon.ico",
            "logo": "https://www.hudsonrock.com/logo.png",
            "description": "Hudson Rock provides free cybercrime intelligence powered by their "
            "Cavalier database of infostealer malware compromises. The free OSINT API "
            "returns data on compromised credentials from infected machines, including "
            "affected URLs, stolen cookies, and computer metadata.",
        },
    }

    opts = {
        "api_key": "",
        "request_delay": 1.0,
    }

    optdescs = {
        "api_key": "Hudson Rock Cavalier API key (optional — free OSINT endpoints work without a key).",
        "request_delay": "Delay between API requests in seconds.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["EMAILADDR", "INTERNET_NAME", "DOMAIN_NAME"]

    def producedEvents(self):
        return [
            "LEAKSITE_CONTENT",
            "RAW_RIR_DATA",
            "EMAILADDR_COMPROMISED",
        ]

    def queryEmail(self, email):
        """Query the free OSINT endpoint for email compromise data."""
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email}"

        headers = {}
        if self.opts["api_key"]:
            headers["api-key"] = self.opts["api_key"]

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
            headers=headers,
        )

        time.sleep(self.opts["request_delay"])

        if not res or not res.get("content"):
            return None

        if res["code"] == "429":
            self.error("Hudson Rock rate limit hit.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from Hudson Rock")
            return None

        try:
            return json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing Hudson Rock response: {e}")
            return None

    def queryDomain(self, domain):
        """Query the free OSINT endpoint for domain compromise data."""
        url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}"

        headers = {}
        if self.opts["api_key"]:
            headers["api-key"] = self.opts["api_key"]

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
            headers=headers,
        )

        time.sleep(self.opts["request_delay"])

        if not res or not res.get("content"):
            return None

        if res["code"] == "429":
            self.error("Hudson Rock rate limit hit.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from Hudson Rock")
            return None

        try:
            return json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing Hudson Rock response: {e}")
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

        if eventName == "EMAILADDR":
            data = self.queryEmail(eventData)
            if not data:
                return

            stealers = data.get("stealers", [])
            if not stealers:
                return

            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
            self.notifyListeners(e)

            e = SpiderFootEvent(
                "EMAILADDR_COMPROMISED",
                f"{eventData} [Hudson Rock - Infostealer]",
                self.__name__,
                event,
            )
            self.notifyListeners(e)

            for stealer in stealers:
                computer_name = stealer.get("computer_name", "Unknown")
                operating_system = stealer.get("operating_system", "Unknown")
                date_compromised = stealer.get("date_compromised", "Unknown")
                malware_path = stealer.get("malware_path", "Unknown")

                descr = f"Hudson Rock - Infostealer Compromise Detected [{eventData}]\n"
                descr += f" - Computer: {computer_name}\n"
                descr += f" - OS: {operating_system}\n"
                descr += f" - Date Compromised: {date_compromised}\n"
                descr += f" - Malware Path: {malware_path}\n"
                descr += "<SFURL>https://www.hudsonrock.com/</SFURL>"

                e = SpiderFootEvent("LEAKSITE_CONTENT", descr, self.__name__, event)
                self.notifyListeners(e)

        elif eventName in ["INTERNET_NAME", "DOMAIN_NAME"]:
            data = self.queryDomain(eventData)
            if not data:
                return

            stealers = data.get("stealers", [])
            if not stealers:
                return

            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
            self.notifyListeners(e)

            for stealer in stealers:
                computer_name = stealer.get("computer_name", "Unknown")
                date_compromised = stealer.get("date_compromised", "Unknown")
                employee_count = data.get("total_employees_exposed", "Unknown")

                descr = f"Hudson Rock - Domain Compromise via Infostealer [{eventData}]\n"
                descr += f" - Computer: {computer_name}\n"
                descr += f" - Date Compromised: {date_compromised}\n"
                descr += f" - Total Employees Exposed: {employee_count}\n"
                descr += "<SFURL>https://www.hudsonrock.com/</SFURL>"

                e = SpiderFootEvent("LEAKSITE_CONTENT", descr, self.__name__, event)
                self.notifyListeners(e)


# End of sfp_hudsonrock class
