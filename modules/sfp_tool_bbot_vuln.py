# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_bbot_vuln
# Purpose:      SpiderFoot plug-in for using BBOT for vulnerability detection
#               (nuclei, badsecrets, baddns, wpscan).
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
import re
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_bbot_vuln(SpiderFootPlugin):

    meta = {
        "name": "Tool - BBOT Vulnerability Scanner",
        "summary": "Use BBOT for vulnerability detection via nuclei, badsecrets, baddns, and wpscan modules.",
        "flags": ["tool", "slow", "invasive"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "name": "BBOT",
            "description": "BBOT vulnerability scanning combines nuclei templates, badsecrets "
            "(known/weak secrets in web frameworks), baddns (subdomain takeover detection), "
            "and wpscan (WordPress security).",
            "website": "https://github.com/blacklanternsecurity/bbot",
            "repository": "https://github.com/blacklanternsecurity/bbot",
        },
    }

    opts = {
        "bbot_path": "",
        "modules": "nuclei,badsecrets,baddns",
        "timeout": 900,
    }

    optdescs = {
        "bbot_path": "Path to bbot binary. If empty, assumes 'bbot' is in PATH.",
        "modules": "Comma-separated list of BBOT vulnerability scan modules to enable.",
        "timeout": "Maximum scan time in seconds (default: 900).",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["INTERNET_NAME", "IP_ADDRESS"]

    def producedEvents(self):
        return [
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "VULNERABILITY_GENERAL",
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

        modules = [m.strip() for m in self.opts["modules"].split(",")]

        args = [
            exe,
            "-t", eventData,
            "-m", *modules,
            "--json",
            "--silent",
            "-y",
            "--no-deps",
        ]

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            try:
                stdout, stderr = p.communicate(timeout=self.opts["timeout"])
                content = stdout.decode("utf-8", errors="replace")
            except TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                self.debug("BBOT vuln scan timed out")
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

            if evt_type == "VULNERABILITY":
                severity = ""
                if isinstance(evt_data, dict):
                    severity = evt_data.get("severity", "").upper()
                    description = evt_data.get("description", str(evt_data))
                    host = evt_data.get("host", eventData)
                else:
                    description = str(evt_data)
                    host = eventData

                # Check for CVEs
                cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", str(evt_data))
                if cve_matches:
                    for cve in cve_matches:
                        etype, cvetext = self.sf.cveInfo(cve)
                        e = SpiderFootEvent(etype, cvetext, self.__name__, event)
                        self.notifyListeners(e)
                else:
                    descr = f"BBOT Vulnerability [{host}]\n"
                    descr += f" - Severity: {severity}\n"
                    descr += f" - Details: {description}\n"
                    descr += f" - Module: {data.get('module', 'unknown')}"

                    e = SpiderFootEvent("VULNERABILITY_GENERAL", descr, self.__name__, event)
                    self.notifyListeners(e)

            elif evt_type == "FINDING":
                if isinstance(evt_data, dict):
                    description = evt_data.get("description", str(evt_data))
                    host = evt_data.get("host", eventData)
                else:
                    description = str(evt_data)
                    host = eventData

                descr = f"BBOT Finding [{host}]\n"
                descr += f" - Details: {description}\n"
                descr += f" - Module: {data.get('module', 'unknown')}"

                e = SpiderFootEvent("VULNERABILITY_GENERAL", descr, self.__name__, event)
                self.notifyListeners(e)

            if evt_type in ("VULNERABILITY", "FINDING"):
                e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
                self.notifyListeners(e)


# End of sfp_tool_bbot_vuln class
