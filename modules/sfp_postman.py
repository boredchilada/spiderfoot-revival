# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_postman
# Purpose:      Discover public Postman workspaces and collections associated
#               with a target organization for leaked API keys and endpoints.
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


class sfp_postman(SpiderFootPlugin):

    meta = {
        "name": "Postman",
        "summary": "Search for public Postman workspaces and collections that may contain leaked API keys, credentials, and internal endpoints.",
        "flags": [],
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Leaks, Dumps and Breaches"],
        "dataSource": {
            "website": "https://www.postman.com/",
            "model": "FREE_NOAUTH_UNLIMITED",
            "references": [
                "https://www.postman.com/explore",
            ],
            "favIcon": "https://www.postman.com/favicon.ico",
            "logo": "https://www.postman.com/_ar-assets/images/postman-logo-icon-orange.svg",
            "description": "Postman's public API network contains 200,000+ public workspaces. "
            "Research shows ~1.8% of public workspaces contain leaked secrets including "
            "API keys, tokens, and credentials from 183+ SaaS providers. This module searches "
            "for workspaces related to your target domain or organization.",
        },
    }

    opts = {
        "max_pages": 5,
        "request_delay": 1.0,
    }

    optdescs = {
        "max_pages": "Maximum number of search result pages to retrieve (25 results per page).",
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
        return ["DOMAIN_NAME", "COMPANY_NAME"]

    def producedEvents(self):
        return [
            "PUBLIC_CODE_REPO",
            "RAW_RIR_DATA",
        ]

    def searchPostman(self, query, page=0):
        """Search Postman's public workspace search API."""
        url = "https://www.postman.com/_api/ws/proxy"

        headers = {
            "Content-Type": "application/json",
            "X-App-Version": "11.27.4-250109-2338",
            "X-Entity-Team-Id": "0",
            "Origin": "https://www.postman.com",
            "Referer": "https://www.postman.com/search?q=&scope=public&type=all",
        }

        payload = json.dumps({
            "service": "search",
            "method": "POST",
            "path": "/search-all",
            "body": {
                "queryIndices": ["collaboration.workspace"],
                "queryText": query,
                "size": 25,
                "from": page * 25,
                "requestOrigin": "srp",
                "mergeEntities": "true",
                "nonNestedRequests": "true",
                "domain": "public",
            },
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

        if res["code"] == "429":
            self.error("Postman search rate limit hit.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from Postman")
            return None

        try:
            return json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing Postman response: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already searched.")
            return

        self.results[eventData] = True

        for page in range(self.opts["max_pages"]):
            if self.checkForStop():
                return

            data = self.searchPostman(eventData, page)
            if not data:
                break

            # Navigate to the data array
            items = data.get("data", [])
            if not items:
                break

            found_any = False
            for item in items:
                doc = item.get("document", {})
                workspace_name = doc.get("name", "")
                publisher_handle = doc.get("publisherHandle", "")
                slug = doc.get("slug", workspace_name)
                summary = doc.get("summary", "")

                if not workspace_name:
                    continue

                workspace_url = f"https://www.postman.com/{publisher_handle}/{slug}"

                if workspace_url in self.results:
                    continue

                self.results[workspace_url] = True
                found_any = True

                descr = f"Postman Public Workspace: {workspace_name}\n"
                if summary:
                    descr += f" - Summary: {summary[:200]}\n"
                descr += f" - Publisher: {publisher_handle}\n"
                descr += f"<SFURL>{workspace_url}</SFURL>"

                e = SpiderFootEvent("PUBLIC_CODE_REPO", descr, self.__name__, event)
                self.notifyListeners(e)

                e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(item), self.__name__, event)
                self.notifyListeners(e)

            if not found_any:
                break


# End of sfp_postman class
