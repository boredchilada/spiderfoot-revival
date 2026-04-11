# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_c2tracker
# Purpose:      Check IP addresses against the C2-Tracker live feed of known
#               command and control server IPs.
#
# Author:       SpiderFoot Revival Project
#
# Created:      2026-04-08
# Copyright:    (c) SpiderFoot Revival Project
# Licence:      MIT
# -------------------------------------------------------------------------------

import time

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_c2tracker(SpiderFootPlugin):

    meta = {
        "name": "C2 Tracker",
        "summary": "Check if IP addresses appear in the C2-Tracker live feed of known command and control servers (Cobalt Strike, Sliver, Havoc, Mythic, etc.).",
        "flags": [],
        "useCases": ["Investigate", "Passive"],
        "categories": ["Reputation Systems"],
        "dataSource": {
            "website": "https://github.com/montysecurity/C2-Tracker",
            "model": "FREE_NOAUTH_UNLIMITED",
            "references": [
                "https://github.com/montysecurity/C2-Tracker",
            ],
            "favIcon": "https://github.com/favicon.ico",
            "logo": "https://github.com/favicon.ico",
            "description": "C2-Tracker provides a community-driven, regularly updated feed of live "
            "command and control (C2) server IP addresses. It tracks Cobalt Strike, Havoc, "
            "Sliver, Mythic, Brute Ratel, Posh, and many other C2 frameworks via Shodan/Censys "
            "queries. Updated weekly. Very high signal — if an IP matches, it is likely active "
            "malicious infrastructure.",
        },
    }

    opts = {
        "checkaffiliates": True,
        "netblocklookup": True,
        "maxnetblock": 24,
        "subnetlookup": True,
        "maxsubnet": 24,
        "cache_hours": 24,
    }

    optdescs = {
        "checkaffiliates": "Check affiliate IP addresses against C2 tracker?",
        "netblocklookup": "Look up all IPs in owned netblocks for C2 matches?",
        "maxnetblock": "Maximum netblock size to scan (CIDR value, 24 = /24).",
        "subnetlookup": "Look up all IPs in subnets for C2 matches?",
        "maxsubnet": "Maximum subnet size to scan (CIDR value, 24 = /24).",
        "cache_hours": "Hours to cache the C2 IP list before re-fetching (default: 24).",
    }

    results = None
    errorState = False
    c2_ips = None
    c2_last_fetched = 0

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.c2_ips = None
        self.c2_last_fetched = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "NETBLOCK_MEMBER", "NETBLOCK_OWNER"]

    def producedEvents(self):
        return [
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "MALICIOUS_SUBNET",
        ]

    def _fetchC2List(self):
        """Fetch and cache the C2 IP list from GitHub."""
        now = time.time()
        cache_seconds = self.opts["cache_hours"] * 3600

        if self.c2_ips is not None and (now - self.c2_last_fetched) < cache_seconds:
            return self.c2_ips

        url = "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt"

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
        )

        if not res or not res.get("content"):
            self.error("Unable to fetch C2-Tracker IP list.")
            self.errorState = True
            return set()

        if res["code"] != "200":
            self.error(f"Bad response code {res['code']} from C2-Tracker")
            return set()

        self.c2_ips = set()
        for line in res["content"].split("\n"):
            ip = line.strip()
            if ip and not ip.startswith("#"):
                self.c2_ips.add(ip)

        self.c2_last_fetched = now
        self.debug(f"Loaded {len(self.c2_ips)} C2 IPs from C2-Tracker")
        return self.c2_ips

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "NETBLOCK_OWNER":
            if not self.opts["netblocklookup"]:
                return
            if IPNetwork(eventData).prefixlen < self.opts["maxnetblock"]:
                self.debug(f"Network size bigger than permitted: {eventData}")
                return

        if eventName == "NETBLOCK_MEMBER":
            if not self.opts["subnetlookup"]:
                return
            if IPNetwork(eventData).prefixlen < self.opts["maxsubnet"]:
                self.debug(f"Network size bigger than permitted: {eventData}")
                return

        if eventName == "AFFILIATE_IPADDR" and not self.opts["checkaffiliates"]:
            return

        c2_ips = self._fetchC2List()
        if not c2_ips:
            return

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for addr in IPNetwork(eventData):
                qrylist.append(str(addr))
        else:
            qrylist.append(eventData)

        for addr in qrylist:
            if addr not in c2_ips:
                continue

            self.info(f"C2-Tracker: {addr} is a known C2 server!")

            descr = f"C2-Tracker - Known C2 Server [{addr}]\n"
            descr += " - This IP is listed in the C2-Tracker live feed of active\n"
            descr += "   command and control infrastructure (Cobalt Strike, Sliver, etc.)\n"
            descr += "<SFURL>https://github.com/montysecurity/C2-Tracker</SFURL>"

            if eventName == "AFFILIATE_IPADDR":
                evt_type = "MALICIOUS_AFFILIATE_IPADDR"
            elif eventName == "NETBLOCK_OWNER":
                evt_type = "MALICIOUS_NETBLOCK"
            elif eventName == "NETBLOCK_MEMBER":
                evt_type = "MALICIOUS_SUBNET"
            else:
                evt_type = "MALICIOUS_IPADDR"

            e = SpiderFootEvent(evt_type, descr, self.__name__, event)
            self.notifyListeners(e)


# End of sfp_c2tracker class
