# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_misp
# Purpose:      Query a MISP instance for threat intelligence on IPs, domains,
#               email addresses, and hashes found during scans.
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


class sfp_misp(SpiderFootPlugin):

    meta = {
        "name": "MISP",
        "summary": "Query a MISP Threat Intelligence Sharing Platform instance for known indicators matching IPs, domains, emails, and hashes found during scans.",
        "flags": ["apikey"],
        "useCases": ["Investigate", "Passive"],
        "categories": ["Reputation Systems"],
        "dataSource": {
            "website": "https://www.misp-project.org/",
            "model": "FREE_AUTH_UNLIMITED",
            "references": [
                "https://www.misp-project.org/openapi/",
                "https://pypi.org/project/pymisp/",
            ],
            "apiKeyInstructions": [
                "Deploy a MISP instance or get access to a shared one",
                "Navigate to your MISP user profile",
                "Copy the Auth Key from your profile page",
            ],
            "favIcon": "https://www.misp-project.org/favicon.ico",
            "logo": "https://www.misp-project.org/assets/images/misp-small.png",
            "description": "MISP is the de facto standard open-source threat intelligence sharing "
            "platform. It stores, correlates, and distributes structured threat data including "
            "IOCs, threat actor info, and campaign data. This module queries your MISP instance "
            "for any indicators that match what SpiderFoot discovers during scans.",
        },
    }

    opts = {
        "api_key": "",
        "instance_url": "",
        "request_delay": 0.5,
        "include_event_info": True,
    }

    optdescs = {
        "api_key": "MISP API/Auth key.",
        "instance_url": "URL of your MISP instance (e.g., https://misp.yourdomain.com).",
        "request_delay": "Delay between API requests in seconds.",
        "include_event_info": "Include MISP event titles and tags in results.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "AFFILIATE_IPADDR",
            "INTERNET_NAME",
            "DOMAIN_NAME",
            "EMAILADDR",
            "HASH",
            "LINKED_URL_EXTERNAL",
        ]

    def producedEvents(self):
        return [
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_EMAILADDR",
            "RAW_RIR_DATA",
        ]

    def queryMISP(self, indicator):
        """Search MISP for an indicator via the REST API."""
        url = f"{self.opts['instance_url'].rstrip('/')}/attributes/restSearch"

        headers = {
            "Authorization": self.opts["api_key"],
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        payload = json.dumps({
            "returnFormat": "json",
            "value": indicator,
            "limit": 50,
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

        if res["code"] in ["401", "403"]:
            self.error("MISP API key is invalid or insufficient permissions.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from MISP")
            return None

        try:
            data = json.loads(res["content"])
            response = data.get("response", {})
            attributes = response.get("Attribute", [])
            return attributes if attributes else None
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing MISP response: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if not self.opts["api_key"] or not self.opts["instance_url"]:
            self.error("You enabled sfp_misp but did not set an API key and instance URL!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        attributes = self.queryMISP(eventData)
        if not attributes:
            return

        e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(attributes), self.__name__, event)
        self.notifyListeners(e)

        # Determine the malicious event type based on input
        evt_type_map = {
            "IP_ADDRESS": "MALICIOUS_IPADDR",
            "AFFILIATE_IPADDR": "MALICIOUS_AFFILIATE_IPADDR",
            "INTERNET_NAME": "MALICIOUS_INTERNET_NAME",
            "DOMAIN_NAME": "MALICIOUS_INTERNET_NAME",
            "EMAILADDR": "MALICIOUS_EMAILADDR",
            "HASH": "MALICIOUS_INTERNET_NAME",
            "LINKED_URL_EXTERNAL": "MALICIOUS_INTERNET_NAME",
        }

        evt_type = evt_type_map.get(eventName, "MALICIOUS_INTERNET_NAME")

        # Deduplicate by MISP event ID
        seen_events = set()
        for attr in attributes:
            event_id = attr.get("event_id", "")
            if event_id in seen_events:
                continue
            seen_events.add(event_id)

            category = attr.get("category", "Unknown")
            attr_type = attr.get("type", "Unknown")
            comment = attr.get("comment", "")

            descr = f"MISP - Threat Intel Match [{eventData}]\n"
            descr += f" - Category: {category}\n"
            descr += f" - Type: {attr_type}\n"
            if comment:
                descr += f" - Comment: {comment}\n"

            if self.opts["include_event_info"]:
                event_info = attr.get("Event", {})
                if event_info:
                    descr += f" - Event: {event_info.get('info', 'N/A')}\n"
                    tags = event_info.get("Tag", [])
                    if tags:
                        tag_names = [t.get("name", "") for t in tags[:5]]
                        descr += f" - Tags: {', '.join(tag_names)}\n"

            descr += f"<SFURL>{self.opts['instance_url']}/events/view/{event_id}</SFURL>"

            e = SpiderFootEvent(evt_type, descr, self.__name__, event)
            self.notifyListeners(e)


# End of sfp_misp class
