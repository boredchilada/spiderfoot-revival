# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ransomlook
# Purpose:      Query RansomLook API to check if a target organization has been
#               listed as a ransomware victim.
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


class sfp_ransomlook(SpiderFootPlugin):

    meta = {
        "name": "RansomLook",
        "summary": "Check if a target domain or organization has appeared as a victim on ransomware gang leak sites.",
        "flags": [],
        "useCases": ["Investigate", "Passive"],
        "categories": ["Reputation Systems"],
        "dataSource": {
            "website": "https://www.ransomlook.io/",
            "model": "FREE_NOAUTH_UNLIMITED",
            "references": [
                "https://www.ransomlook.io/doc/",
            ],
            "favIcon": "https://www.ransomlook.io/favicon.ico",
            "logo": "https://www.ransomlook.io/logo.png",
            "description": "RansomLook tracks ransomware gang activity by monitoring their leak sites, "
            "blogs, and Telegram channels. It provides a free API with no authentication required "
            "to search for victim organizations across all tracked ransomware groups. "
            "Data is licensed CC BY 4.0.",
        },
    }

    opts = {
        "request_delay": 1.0,
    }

    optdescs = {
        "request_delay": "Delay between API requests in seconds.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME", "COMPANY_NAME"]

    def producedEvents(self):
        return [
            "DARKNET_MENTION_CONTENT",
            "RAW_RIR_DATA",
        ]

    def querySearch(self, query):
        """Search RansomLook for a victim name/domain."""
        url = f"https://www.ransomlook.io/api/search?q={query}"

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
        )

        time.sleep(self.opts["request_delay"])

        if not res or not res.get("content"):
            return None

        if res["code"] == "429":
            self.error("RansomLook rate limit hit.")
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from RansomLook")
            return None

        try:
            return json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing RansomLook response: {e}")
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

        # For domains, search the base domain (strip subdomains)
        search_term = eventData
        if eventName in ["DOMAIN_NAME", "INTERNET_NAME"]:
            # Also try without TLD for broader matching
            parts = eventData.split(".")
            if len(parts) >= 2:
                search_term = parts[-2]  # e.g., "example" from "example.com"

        data = self.querySearch(search_term)
        if not data:
            return

        # RansomLook returns results grouped by type (groups, posts, etc.)
        posts = data.get("posts", [])
        if not posts and isinstance(data, list):
            posts = data

        if not posts:
            return

        e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
        self.notifyListeners(e)

        for post in posts:
            if isinstance(post, dict):
                title = post.get("title", post.get("post_title", ""))
                group = post.get("group_name", post.get("group", "Unknown"))
                discovered = post.get("discovered", post.get("date", "Unknown"))
                description = post.get("description", "")

                # Verify the result actually relates to our target
                if eventData.lower() not in title.lower() and search_term.lower() not in title.lower():
                    continue

                descr = f"RansomLook - Ransomware Victim Post [{eventData}]\n"
                descr += f" - Group: {group}\n"
                descr += f" - Title: {title}\n"
                descr += f" - Discovered: {discovered}\n"
                if description:
                    descr += f" - Description: {description[:200]}\n"
                descr += "<SFURL>https://www.ransomlook.io/</SFURL>"

                e = SpiderFootEvent("DARKNET_MENTION_CONTENT", descr, self.__name__, event)
                self.notifyListeners(e)


# End of sfp_ransomlook class
