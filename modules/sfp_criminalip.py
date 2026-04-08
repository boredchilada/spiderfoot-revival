# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_criminalip
# Purpose:      Query Criminal IP for IP/domain threat intelligence.
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


class sfp_criminalip(SpiderFootPlugin):

    meta = {
        "name": "Criminal IP",
        "summary": "Query Criminal IP for threat intelligence on IP addresses including open ports, vulnerabilities, VPN detection, and risk scoring.",
        "flags": ["apikey"],
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Reputation Systems"],
        "dataSource": {
            "website": "https://www.criminalip.io/",
            "model": "FREE_AUTH_LIMITED",
            "references": [
                "https://search.criminalip.io/developer/api/",
            ],
            "apiKeyInstructions": [
                "Visit https://www.criminalip.io/",
                "Sign up for a free account",
                "Navigate to https://www.criminalip.io/mypage/information",
                "The API key is listed on your account page",
            ],
            "favIcon": "https://www.criminalip.io/favicon.ico",
            "logo": "https://www.criminalip.io/logo.png",
            "description": "Criminal IP is a cyber threat intelligence search engine that provides "
            "IP risk scoring, open port detection, vulnerability analysis, VPN/proxy detection, "
            "and malicious IP classification. Free tier includes limited credits on signup.",
        },
    }

    opts = {
        "api_key": "",
        "netblocklookup": True,
        "maxnetblock": 24,
        "subnetlookup": True,
        "maxsubnet": 24,
        "request_delay": 1.0,
    }

    optdescs = {
        "api_key": "Criminal IP API key.",
        "netblocklookup": "Look up netblocks deemed to be owned by your target?",
        "maxnetblock": "Maximum netblock/subnet size to scan IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        "subnetlookup": "Look up subnets which your target is a part of?",
        "maxsubnet": "Maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
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
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "NETBLOCK_MEMBER", "NETBLOCK_OWNER"]

    def producedEvents(self):
        return [
            "TCP_PORT_OPEN",
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "GEOINFO",
            "BGP_AS_MEMBER",
            "COMPANY_NAME",
            "RAW_RIR_DATA",
        ]

    def queryIP(self, ip):
        """Query Criminal IP for an IP report summary."""
        url = f"https://api.criminalip.io/v1/asset/ip/report/summary?ip={ip}"

        headers = {"x-api-key": self.opts["api_key"]}

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
            self.error("Criminal IP API key is invalid.")
            self.errorState = True
            return None

        if res["code"] == "429":
            self.error("Criminal IP rate/credit limit hit.")
            self.errorState = True
            return None

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from Criminal IP")
            return None

        try:
            data = json.loads(res["content"])
            if data.get("status") != 200:
                self.debug(f"Criminal IP returned error status for {ip}")
                return None
            return data
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing Criminal IP response: {e}")
            return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if not self.opts["api_key"]:
            self.error("You enabled sfp_criminalip but did not set an API key!")
            self.errorState = True
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

        if eventName == "AFFILIATE_IPADDR":
            evtType = "MALICIOUS_AFFILIATE_IPADDR"
        else:
            evtType = "MALICIOUS_IPADDR"

        for addr in qrylist:
            if self.checkForStop():
                return

            if addr in self.results:
                continue

            self.results[addr] = True

            rec = self.queryIP(addr)
            if not rec:
                continue

            data = rec.get("data", {})
            if not data:
                continue

            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(rec), self.__name__, event)
            self.notifyListeners(e)

            # Open ports
            for port_info in data.get("issues", {}).get("is_open_ports", []):
                if isinstance(port_info, dict):
                    port = port_info.get("port")
                    if port:
                        e = SpiderFootEvent("TCP_PORT_OPEN", f"{addr}:{port}", self.__name__, event)
                        self.notifyListeners(e)

            # Vulnerabilities
            for vuln in data.get("issues", {}).get("is_vulnerability", []):
                if isinstance(vuln, dict):
                    cve_id = vuln.get("cve_id", "")
                    if cve_id:
                        etype, cvetext = self.sf.cveInfo(cve_id)
                        e = SpiderFootEvent(etype, cvetext, self.__name__, event)
                        self.notifyListeners(e)

            # Risk scoring — report if malicious
            score = data.get("scores", {})
            inbound = score.get("inbound", "")
            outbound = score.get("outbound", "")
            if inbound in ["critical", "dangerous"] or outbound in ["critical", "dangerous"]:
                descr = f"Criminal IP - Malicious IP Detected [{addr}]\n"
                descr += f" - Inbound Score: {inbound}\n"
                descr += f" - Outbound Score: {outbound}\n"
                descr += f"<SFURL>https://www.criminalip.io/asset/report/{addr}</SFURL>"

                e = SpiderFootEvent(evtType, descr, self.__name__, event)
                self.notifyListeners(e)

            # Geo info
            country = data.get("ip_info", {}).get("country", "")
            city = data.get("ip_info", {}).get("city", "")
            if country:
                loc = f"{city}, {country}" if city else country
                e = SpiderFootEvent("GEOINFO", loc, self.__name__, event)
                self.notifyListeners(e)

            # ASN
            asn = data.get("ip_info", {}).get("as_no", "")
            if asn:
                e = SpiderFootEvent("BGP_AS_MEMBER", str(asn), self.__name__, event)
                self.notifyListeners(e)

            # Organization
            org = data.get("ip_info", {}).get("org_name", "")
            if org:
                e = SpiderFootEvent("COMPANY_NAME", org, self.__name__, event)
                self.notifyListeners(e)


# End of sfp_criminalip class
