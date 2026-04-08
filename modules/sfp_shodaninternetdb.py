# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_shodaninternetdb
# Purpose:      Query Shodan's free InternetDB API for IP enrichment.
#
# Author:       SpiderFoot Revival Project
#
# Created:      2026-04-08
# Copyright:    (c) SpiderFoot Revival Project
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import time

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_shodaninternetdb(SpiderFootPlugin):

    meta = {
        "name": "Shodan InternetDB",
        "summary": "Query Shodan's free InternetDB API for open ports, vulnerabilities, hostnames, and CPEs of IP addresses.",
        "flags": [],
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Search Engines"],
        "dataSource": {
            "website": "https://internetdb.shodan.io/",
            "model": "FREE_NOAUTH_UNLIMITED",
            "references": [
                "https://internetdb.shodan.io/docs",
            ],
            "favIcon": "https://static.shodan.io/shodan/img/favicon.png",
            "logo": "https://static.shodan.io/developer/img/logo.png",
            "description": "The Shodan InternetDB API provides a fast way to see the open ports, "
            "vulnerabilities, hostnames, and CPEs for any IP address. It is updated weekly "
            "and requires no API key or account.",
        },
    }

    opts = {
        "netblocklookup": True,
        "maxnetblock": 24,
        "subnetlookup": True,
        "maxsubnet": 24,
        "request_delay": 1.0,
    }

    optdescs = {
        "netblocklookup": "Look up netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?",
        "maxnetblock": "Maximum netblock/subnet size to scan IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        "subnetlookup": "Look up subnets which your target is a part of?",
        "maxsubnet": "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        "request_delay": "Delay between API requests in seconds (recommended: 1.0 to avoid rate limiting).",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "NETBLOCK_MEMBER", "NETBLOCK_OWNER"]

    def producedEvents(self):
        return [
            "TCP_PORT_OPEN",
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "VULNERABILITY_GENERAL",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "WEBSERVER_TECHNOLOGY",
            "RAW_RIR_DATA",
        ]

    def queryIP(self, ip):
        """Query the InternetDB API for a single IP."""
        url = f"https://internetdb.shodan.io/{ip}"

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts.get("_useragent", "SpiderFoot"),
        )

        time.sleep(self.opts["request_delay"])

        if not res:
            return None

        if res["code"] == "404":
            self.debug(f"No InternetDB data for {ip}")
            return None

        if res["code"] == "429":
            self.error("Shodan InternetDB rate limit hit. Increase request_delay.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} for {ip}")
            return None

        try:
            return json.loads(res["content"])
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing InternetDB response for {ip}: {e}")
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

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for addr in IPNetwork(eventData):
                qrylist.append(str(addr))
        else:
            qrylist.append(eventData)

        for addr in qrylist:
            if self.checkForStop():
                return

            if addr in self.results:
                continue

            self.results[addr] = True

            rec = self.queryIP(addr)
            if not rec:
                continue

            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(rec), self.__name__, event)
            self.notifyListeners(e)

            # Open ports
            for port in rec.get("ports", []):
                e = SpiderFootEvent(
                    "TCP_PORT_OPEN", f"{addr}:{port}", self.__name__, event
                )
                self.notifyListeners(e)

            # Vulnerabilities (CVEs)
            for cve in rec.get("vulns", []):
                etype, cvetext = self.sf.cveInfo(cve)
                e = SpiderFootEvent(etype, cvetext, self.__name__, event)
                self.notifyListeners(e)

            # Hostnames
            for hostname in rec.get("hostnames", []):
                if self.getTarget().matches(hostname):
                    e = SpiderFootEvent(
                        "INTERNET_NAME", hostname, self.__name__, event
                    )
                    self.notifyListeners(e)
                else:
                    e = SpiderFootEvent(
                        "INTERNET_NAME_UNRESOLVED", hostname, self.__name__, event
                    )
                    self.notifyListeners(e)

            # CPEs as technology info
            for cpe in rec.get("cpes", []):
                e = SpiderFootEvent(
                    "WEBSERVER_TECHNOLOGY", cpe, self.__name__, event
                )
                self.notifyListeners(e)


# End of sfp_shodaninternetdb class
