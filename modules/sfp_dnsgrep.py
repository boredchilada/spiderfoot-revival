# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_dnsgrep
# Purpose:     SpiderFoot plug-in for retrieving domain names
#              from Rapid7 Sonar Project data sets using DNSGrep API.
#              - https://opendata.rapid7.com/about/
#              - https://blog.erbbysam.com/index.php/2019/02/09/dnsgrep/
#              - https://github.com/erbbysam/DNSGrep
#
# Author:      <bcoles@gmail.com>
#
# Created:     2020-03-14
# Copyright:   (c) bcoles 2020
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_dnsgrep(SpiderFootPlugin):

    meta = {
        'name': "DNSGrep",
        'summary': "Obtain Passive DNS information from BufferOver.run (formerly DNSGrep/Rapid7 Sonar).",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Passive DNS"],
        'dataSource': {
            'website': "https://tls.bufferover.run/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://tls.bufferover.run/",
            ],
            'apiKeyInstructions': [
                "Visit https://tls.bufferover.run/",
                "Sign up for a free API key via RapidAPI",
                "The free tier has limited queries per month",
            ],
            'favIcon': "https://www.rapid7.com/includes/img/favicon.ico",
            'logo': "https://www.rapid7.com/includes/img/Rapid7_logo.svg",
            'description': "BufferOver.run provides DNS data derived from Rapid7 Sonar Project datasets. "
            "The service now requires an API key (freemium model via RapidAPI). "
            "Queries return forward DNS (FDNS) and reverse DNS (RDNS) records.",
        }
    }

    # Default options
    opts = {
        'api_key': '',
        'timeout': 30,
        'dns_resolve': True
    }

    # Option descriptions
    optdescs = {
        'api_key': "BufferOver.run API key (x-api-key header). Required for access.",
        'timeout': "Query timeout, in seconds.",
        'dns_resolve': "DNS resolve each identified domain."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED", "RAW_RIR_DATA"]

    # Query the BufferOver.run API
    def query(self, qry):
        if not self.opts.get('api_key'):
            self.error("You enabled sfp_dnsgrep but did not set an API key! "
                       "BufferOver.run now requires an API key.")
            self.errorState = True
            return None

        params = {
            'q': '.' + qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }

        headers = {
            'x-api-key': self.opts['api_key']
        }

        res = self.sf.fetchUrl('https://tls.bufferover.run/dns?' + urllib.parse.urlencode(params),
                               timeout=self.opts['timeout'],
                               useragent=self.opts['_useragent'],
                               headers=headers)

        if not res or res['content'] is None:
            self.info("No results found for " + qry)
            return None

        if res['code'] != '200':
            self.debug("Error retrieving search results for " + qry)
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from DNSGrep: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            return
        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        data = self.query(eventData)

        if data is None:
            self.info("No DNS records found for " + eventData)
            return

        evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
        self.notifyListeners(evt)

        domains = list()

        # Forward DNS A records
        fdns = data.get("FDNS_A")
        if fdns:
            for r in fdns:
                try:
                    ip, domain = r.split(',')
                except Exception:
                    continue

                domains.append(domain)

        # Reverse DNS records
        rdns = data.get("RDNS")
        if rdns:
            for r in rdns:
                try:
                    ip, domain = r.split(',')
                except Exception:
                    continue

                domains.append(domain)

        for domain in domains:
            if domain in self.results:
                continue

            if not self.getTarget().matches(domain, includeParents=True):
                continue

            evt_type = "INTERNET_NAME"

            if self.opts["dns_resolve"] and not self.sf.resolveHost(domain) and not self.sf.resolveHost6(domain):
                self.debug(f"Host {domain} could not be resolved")
                evt_type += "_UNRESOLVED"

            evt = SpiderFootEvent(evt_type, domain, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_dnsgrep class
