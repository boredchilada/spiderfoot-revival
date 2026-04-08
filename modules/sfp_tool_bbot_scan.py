# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_bbot_scan
# Purpose:      SpiderFoot plug-in for using BBOT for active scanning
#               (port scanning, service fingerprinting, SSL certs).
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

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin, SpiderFootHelpers


class sfp_tool_bbot_scan(SpiderFootPlugin):

    meta = {
        "name": "Tool - BBOT Active Scanner",
        "summary": "Use BBOT for active port scanning, HTTP probing, service fingerprinting, and SSL certificate analysis.",
        "flags": ["tool", "slow", "invasive"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "name": "BBOT",
            "description": "BBOT active scanning modules provide port scanning via masscan, "
            "HTTP probing via httpx, service fingerprinting via fingerprintx, "
            "and SSL certificate extraction.",
            "website": "https://github.com/blacklanternsecurity/bbot",
            "repository": "https://github.com/blacklanternsecurity/bbot",
        },
    }

    opts = {
        "bbot_path": "",
        "modules": "portscan,httpx,sslcert,fingerprintx",
        "top_ports": 100,
        "timeout": 900,
        "netblockscan": True,
        "netblockscanmax": 24,
    }

    optdescs = {
        "bbot_path": "Path to bbot binary. If empty, assumes 'bbot' is in PATH.",
        "modules": "Comma-separated list of BBOT active scan modules to enable.",
        "top_ports": "Number of top ports to scan (default: 100).",
        "timeout": "Maximum scan time in seconds (default: 900).",
        "netblockscan": "Scan all IPs within identified owned netblocks?",
        "netblockscanmax": "Maximum netblock/subnet size to scan (CIDR value, 24 = /24).",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS", "INTERNET_NAME", "NETBLOCK_OWNER"]

    def producedEvents(self):
        return [
            "TCP_PORT_OPEN",
            "UDP_PORT_OPEN",
            "WEBSERVER_BANNER",
            "WEBSERVER_HTTPHEADERS",
            "WEBSERVER_TECHNOLOGY",
            "SSL_CERTIFICATE_ISSUED",
            "IP_ADDRESS",
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

        if eventName == "NETBLOCK_OWNER":
            if not self.opts["netblockscan"]:
                return
            if IPNetwork(eventData).prefixlen < self.opts["netblockscanmax"]:
                self.debug(f"Network size bigger than permitted: {eventData}")
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
            "-c", f"modules.portscan.top_ports={self.opts['top_ports']}",
        ]

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            try:
                stdout, stderr = p.communicate(timeout=self.opts["timeout"])
                content = stdout.decode("utf-8", errors="replace")
            except TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                self.debug("BBOT scan timed out")
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

            if evt_type == "OPEN_TCP_PORT":
                e = SpiderFootEvent("TCP_PORT_OPEN", evt_data, self.__name__, event)
                self.notifyListeners(e)

            elif evt_type == "OPEN_UDP_PORT":
                e = SpiderFootEvent("UDP_PORT_OPEN", evt_data, self.__name__, event)
                self.notifyListeners(e)

            elif evt_type == "HTTP_RESPONSE":
                if isinstance(evt_data, dict):
                    server = evt_data.get("header", {}).get("server", "")
                    if server:
                        e = SpiderFootEvent("WEBSERVER_BANNER", server, self.__name__, event)
                        self.notifyListeners(e)
                e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
                self.notifyListeners(e)

            elif evt_type == "TECHNOLOGY":
                e = SpiderFootEvent("WEBSERVER_TECHNOLOGY", str(evt_data), self.__name__, event)
                self.notifyListeners(e)

            elif evt_type == "SSL_CERTIFICATE":
                if isinstance(evt_data, dict):
                    subject = evt_data.get("subject", {}).get("common_name", str(evt_data))
                else:
                    subject = str(evt_data)
                e = SpiderFootEvent("SSL_CERTIFICATE_ISSUED", subject, self.__name__, event)
                self.notifyListeners(e)

            elif evt_type == "IP_ADDRESS":
                if evt_data not in self.results:
                    self.results[evt_data] = True
                    e = SpiderFootEvent("IP_ADDRESS", evt_data, self.__name__, event)
                    self.notifyListeners(e)


# End of sfp_tool_bbot_scan class
