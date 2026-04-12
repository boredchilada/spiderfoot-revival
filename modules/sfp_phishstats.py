# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_phishstats
# Purpose:     SpiderFoot plugin to search PhishStats API
#              to determine if an IP, domain, or URL is involved in phishing.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     18/05/2020
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time
import urllib.parse

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_phishstats(SpiderFootPlugin):

    meta = {
        'name': "PhishStats",
        'summary': "Check if an IP, domain, or URL is involved in phishing according to PhishStats.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://phishstats.info/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://phishstats.info/#apidoc"
            ],
            'favIcon': "https://phishstats.info/phish.ico",
            'description': "PhishStats is a real time phishing database that gathers "
                           "phishing URLs from several sources. Rate limit: 20 req/min.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24,
        'checkdomains': True,
        'min_score': 3,
    }

    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'checkdomains': "Also check domain names and internet names against PhishStats?",
        'min_score': "Minimum PhishStats score to consider a result malicious (0-10, higher = more confident).",
    }

    results = None
    errorState = False
    _errorCount = 0
    _maxErrors = 10
    _lastRequestTime = 0

    # PhishStats API base URL
    API_BASE = "https://api.phishstats.info/api/phishing"

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self._errorCount = 0
        self._lastRequestTime = 0

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return [
            'IP_ADDRESS',
            'AFFILIATE_IPADDR',
            'INTERNET_NAME',
            'AFFILIATE_INTERNET_NAME',
            'DOMAIN_NAME',
            'AFFILIATE_DOMAIN_NAME',
            "NETBLOCK_MEMBER",
            "NETBLOCK_OWNER",
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET",
            "BLACKLISTED_NETBLOCK",
            "BLACKLISTED_INTERNET_NAME",
            "BLACKLISTED_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "MALICIOUS_SUBNET",
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "RAW_RIR_DATA",
        ]

    def _rateLimit(self):
        """Enforce PhishStats rate limit of 20 requests per minute (3 sec between requests)."""
        elapsed = time.time() - self._lastRequestTime
        if elapsed < 3.0:
            time.sleep(3.0 - elapsed)
        self._lastRequestTime = time.time()

    def _apiQuery(self, where_clause):
        """Run a query against the PhishStats API.

        Args:
            where_clause: PhishStats _where filter string, e.g. "(ip,eq,1.2.3.4)"

        Returns:
            list: parsed JSON response, or None on error
        """
        self._rateLimit()

        params = {
            '_where': where_clause,
            '_size': 5,
            '_sort': '-date',
        }

        headers = {
            'Accept': "application/json",
        }

        res = self.sf.fetchUrl(
            f"{self.API_BASE}?{urllib.parse.urlencode(params)}",
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        if res['code'] in ["0", None]:
            self._errorCount += 1
            if self._errorCount >= self._maxErrors:
                self.error(f"PhishStats API unreachable after {self._errorCount} consecutive failures, giving up.")
                self.errorState = True
            return None

        if res['code'] == "429":
            self._errorCount += 1
            self.debug("PhishStats rate limited, backing off.")
            time.sleep(10)
            if self._errorCount >= self._maxErrors:
                self.error("PhishStats rate limit exceeded too many times, giving up.")
                self.errorState = True
            return None

        if res['code'] != "200":
            self.debug(f"Unexpected response code {res['code']} from PhishStats.")
            return None

        # Reset error counter on success
        self._errorCount = 0

        try:
            data = json.loads(res['content'])
            if not isinstance(data, list):
                return None
            return data
        except Exception as e:
            self.error(f"Error processing JSON response: {e}")

        return None

    def queryIPAddress(self, qry):
        """Check whether an IP address is involved in phishing."""
        return self._apiQuery(f"(ip,eq,{qry})")

    def queryDomain(self, qry):
        """Check whether a domain appears in phishing URLs."""
        return self._apiQuery(f"(url,like,{qry})")

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        # Determine event types based on input
        if eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName == 'IP_ADDRESS':
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName in ('INTERNET_NAME', 'DOMAIN_NAME'):
            if not self.opts.get('checkdomains', False):
                return
            malicious_type = "MALICIOUS_INTERNET_NAME"
            blacklist_type = "BLACKLISTED_INTERNET_NAME"
        elif eventName in ('AFFILIATE_INTERNET_NAME', 'AFFILIATE_DOMAIN_NAME'):
            if not self.opts.get('checkaffiliates', False):
                return
            if not self.opts.get('checkdomains', False):
                return
            malicious_type = "MALICIOUS_AFFILIATE_INTERNET_NAME"
            blacklist_type = "BLACKLISTED_AFFILIATE_INTERNET_NAME"
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return

            max_subnet = self.opts['maxsubnet']
            if IPNetwork(eventData).prefixlen < max_subnet:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_subnet}")
                return

            malicious_type = "MALICIOUS_SUBNET"
            blacklist_type = "BLACKLISTED_SUBNET"
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return

            max_netblock = self.opts['maxnetblock']
            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

            malicious_type = "MALICIOUS_NETBLOCK"
            blacklist_type = "BLACKLISTED_NETBLOCK"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        # Build query list — for netblocks, iterate IPs; otherwise single query
        qrylist = list()
        is_domain_query = eventName in (
            'INTERNET_NAME', 'DOMAIN_NAME',
            'AFFILIATE_INTERNET_NAME', 'AFFILIATE_DOMAIN_NAME'
        )

        if eventName.startswith("NETBLOCK"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        for addr in qrylist:
            if self.checkForStop():
                return

            if self.errorState:
                return

            # Use domain query for hostnames, IP query for addresses
            if is_domain_query:
                data = self.queryDomain(addr)
            else:
                data = self.queryIPAddress(addr)

            if not data:
                continue

            # Filter by minimum score
            min_score = self.opts.get('min_score', 3)
            scored_results = []
            for entry in data:
                try:
                    score = entry.get('score', 0)
                    if score is not None and float(score) >= min_score:
                        scored_results.append(entry)
                except (ValueError, TypeError):
                    scored_results.append(entry)

            if not scored_results:
                continue

            # For IP lookups, verify the returned IP matches
            if not is_domain_query:
                try:
                    maliciousIP = scored_results[0].get('ip')
                except (IndexError, AttributeError):
                    continue

                if not maliciousIP:
                    continue

                if addr != maliciousIP:
                    self.error(f"Reported address {maliciousIP} doesn't match queried IP address {addr}, skipping")
                    continue

            # For netblocks, create the IP address event for context
            if eventName == 'NETBLOCK_OWNER':
                pevent = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            elif eventName == 'NETBLOCK_MEMBER':
                pevent = SpiderFootEvent("AFFILIATE_IPADDR", addr, self.__name__, event)
                self.notifyListeners(pevent)
            else:
                pevent = event

            evt = SpiderFootEvent("RAW_RIR_DATA", str(scored_results), self.__name__, pevent)
            self.notifyListeners(evt)

            text = f"PhishStats [{addr}]"

            evt = SpiderFootEvent(blacklist_type, text, self.__name__, pevent)
            self.notifyListeners(evt)

            evt = SpiderFootEvent(malicious_type, text, self.__name__, pevent)
            self.notifyListeners(evt)

# End of sfp_phishstats class
