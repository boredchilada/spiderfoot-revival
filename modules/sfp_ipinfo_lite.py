# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ipinfo_lite
# Purpose:     SpiderFoot plugin to query IPinfo Lite API for ASN, country,
#              and organization data. Free and unlimited. Replaces BGPView.
#
# Author:      SpiderFoot Revival
#
# Created:     2026-04-11
# Licence:     MIT
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ipinfo_lite(SpiderFootPlugin):

    meta = {
        'name': "IPinfo Lite",
        'summary': "Obtain ASN, organization, and country data for IP addresses "
                   "using the free IPinfo Lite API (unlimited requests).",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://ipinfo.io/lite",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://ipinfo.io/developers/lite-api"
            ],
            'apiKeyInstructions': [
                "Visit https://ipinfo.io/signup",
                "Sign up for a free account (no credit card required)",
                "Navigate to https://ipinfo.io/account/token",
                "Copy your API token"
            ],
            'favIcon': "https://ipinfo.io/static/favicon-96x96.png?v3",
            'logo': "https://ipinfo.io/static/deviceicons/android-icon-96x96.png",
            'description': "IPinfo Lite provides free, unlimited access to accurate "
                           "country-level IP geolocation and ASN data. Data is sourced "
                           "from BGP announcements and enriched with WHOIS records.",
        }
    }

    opts = {
        "api_key": "",
    }

    optdescs = {
        "api_key": "IPinfo Lite API token (free, unlimited).",
    }

    results = None
    errorState = False

    API_BASE = "https://api.ipinfo.io/lite"

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return [
            'IP_ADDRESS',
            'IPV6_ADDRESS',
            'AFFILIATE_IPADDR',
        ]

    def producedEvents(self):
        return [
            'BGP_AS_MEMBER',
            'COMPANY_NAME',
            'GEOINFO',
            'RAW_RIR_DATA',
        ]

    def queryIP(self, ip):
        """Query IPinfo Lite API for a single IP address.

        Args:
            ip: IP address string

        Returns:
            dict: parsed JSON response, or None on error
        """
        api_key = self.opts.get('api_key', '')
        if not api_key:
            self.error("You enabled sfp_ipinfo_lite but did not set an API key!")
            self.errorState = True
            return None

        res = self.sf.fetchUrl(
            f"{self.API_BASE}/{ip}?token={api_key}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['code'] in ["0", None]:
            self.error(f"Failed to connect to IPinfo Lite API for {ip}.")
            return None

        if res['code'] == "401":
            self.error("IPinfo Lite API token is invalid.")
            self.errorState = True
            return None

        if res['code'] == "429":
            self.error("IPinfo Lite rate limited (unexpected — API should be unlimited).")
            return None

        if res['code'] != "200":
            self.debug(f"Unexpected response code {res['code']} from IPinfo Lite for {ip}.")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response: {e}")
            return None

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

        data = self.queryIP(eventData)

        if not data:
            self.info(f"No results found for {eventData}")
            return

        # Emit raw data
        evt = SpiderFootEvent('RAW_RIR_DATA', json.dumps(data, indent=2), self.__name__, event)
        self.notifyListeners(evt)

        # Emit ASN
        asn = data.get('asn')
        if asn:
            evt = SpiderFootEvent('BGP_AS_MEMBER', str(asn), self.__name__, event)
            self.notifyListeners(evt)

        # Emit organization name
        as_name = data.get('as_name')
        if as_name:
            evt = SpiderFootEvent('COMPANY_NAME', as_name, self.__name__, event)
            self.notifyListeners(evt)

        # Emit geolocation
        country = data.get('country')
        continent = data.get('continent')
        country_code = data.get('country_code', '')

        if country:
            geo_parts = [country]
            if continent:
                geo_parts.append(continent)
            geo_str = ', '.join(geo_parts)
            evt = SpiderFootEvent('GEOINFO', geo_str, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_ipinfo_lite class
