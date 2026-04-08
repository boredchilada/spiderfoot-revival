# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_bbot_enum
# Purpose:      SpiderFoot plug-in for using BBOT for subdomain enumeration.
#               Tool: https://github.com/blacklanternsecurity/bbot
#
# Author:       SpiderFoot Revival Project
#
# Created:      2026-04-08
# Copyright:    (c) SpiderFoot Revival Project
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import os
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_bbot_enum(SpiderFootPlugin):

    meta = {
        "name": "Tool - BBOT Subdomain Enumeration",
        "summary": "Use BBOT's subdomain-enum preset to discover subdomains, IPs, and email addresses from 50+ passive sources.",
        "flags": ["tool", "slow"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "name": "BBOT",
            "description": "BBOT is a recursive internet scanner for hackers, inspired by Spiderfoot. "
            "The subdomain-enum preset queries 50+ passive sources including certificate transparency, "
            "passive DNS, web archives, and search engines.",
            "website": "https://github.com/blacklanternsecurity/bbot",
            "repository": "https://github.com/blacklanternsecurity/bbot",
        },
    }

    opts = {
        "bbot_path": "",
        "extra_modules": "",
        "exclude_modules": "",
        "timeout": 600,
    }

    optdescs = {
        "bbot_path": "Path to bbot binary. If empty, assumes 'bbot' is in PATH.",
        "extra_modules": "Comma-separated list of additional BBOT modules to enable (e.g., 'bevigil,chaos').",
        "exclude_modules": "Comma-separated list of BBOT modules to exclude.",
        "timeout": "Maximum scan time in seconds (default: 600).",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME"]

    def producedEvents(self):
        return [
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "IP_ADDRESS",
            "EMAILADDR",
            "RAW_RIR_DATA",
        ]

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already scanned.")
            return

        self.results[eventData] = True

        exe = self.opts["bbot_path"] if self.opts["bbot_path"] else "bbot"
        if self.opts["bbot_path"] and self.opts["bbot_path"].endswith("/"):
            exe = f"{exe}bbot"

        if self.opts["bbot_path"] and not os.path.isfile(exe):
            self.error(f"BBOT binary not found at: {exe}")
            self.errorState = True
            return

        args = [
            exe,
            "-t", eventData,
            "-p", "subdomain-enum",
            "--json",
            "--silent",
            "-y",
        ]

        if self.opts["extra_modules"]:
            args.extend(["-m"] + [m.strip() for m in self.opts["extra_modules"].split(",")])

        if self.opts["exclude_modules"]:
            args.extend(["-em"] + [m.strip() for m in self.opts["exclude_modules"].split(",")])

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            try:
                stdout, stderr = p.communicate(timeout=self.opts["timeout"])
                content = stdout.decode("utf-8", errors="replace")
            except TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                self.debug("BBOT enum timed out")
                content = stdout.decode("utf-8", errors="replace") if stdout else ""
        except Exception as e:
            self.error(f"Unable to run BBOT: {e}")
            self.errorState = True
            return

        if not content:
            return

        for line in content.split("\n"):
            if not line.strip():
                continue

            try:
                data = json.loads(line)
            except (ValueError, TypeError):
                continue

            evt_type = data.get("type", "")
            evt_data = data.get("data", "")

            if not evt_data:
                continue

            if evt_type == "DNS_NAME":
                if evt_data in self.results:
                    continue
                self.results[evt_data] = True
                if self.getTarget().matches(evt_data):
                    e = SpiderFootEvent("INTERNET_NAME", evt_data, self.__name__, event)
                else:
                    e = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", evt_data, self.__name__, event)
                self.notifyListeners(e)

            elif evt_type == "IP_ADDRESS":
                if evt_data in self.results:
                    continue
                self.results[evt_data] = True
                e = SpiderFootEvent("IP_ADDRESS", evt_data, self.__name__, event)
                self.notifyListeners(e)

            elif evt_type == "EMAIL_ADDRESS":
                if evt_data in self.results:
                    continue
                self.results[evt_data] = True
                e = SpiderFootEvent("EMAILADDR", evt_data, self.__name__, event)
                self.notifyListeners(e)

            elif evt_type in ["URL", "URL_UNVERIFIED"]:
                e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
                self.notifyListeners(e)


# End of sfp_tool_bbot_enum class
