# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_vulners
# Purpose:      Query Vulners.com for CVE details, exploits, and software
#               vulnerability data.
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


class sfp_vulners(SpiderFootPlugin):

    meta = {
        "name": "Vulners",
        "summary": "Query Vulners.com vulnerability database for CVE details, exploit availability, and software vulnerability audits.",
        "flags": ["apikey"],
        "useCases": ["Investigate", "Passive"],
        "categories": ["Reputation Systems"],
        "dataSource": {
            "website": "https://vulners.com/",
            "model": "FREE_AUTH_LIMITED",
            "references": [
                "https://docs.vulners.com/docs/api/",
            ],
            "apiKeyInstructions": [
                "Visit https://vulners.com/ and sign up for a free account",
                "Navigate to your account panel",
                "Generate an API key",
            ],
            "favIcon": "https://vulners.com/favicon.ico",
            "logo": "https://vulners.com/logo.png",
            "description": "Vulners is the largest continuously updated vulnerability database with "
            "CVEs, exploits, advisories, and patches from 200+ sources. The /search/id/ endpoint "
            "is completely free (no credits consumed). The software audit endpoint maps detected "
            "software versions to known vulnerabilities.",
        },
    }

    opts = {
        "api_key": "",
        "request_delay": 1.0,
    }

    optdescs = {
        "api_key": "Vulners API key.",
        "request_delay": "Delay between API requests in seconds.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return [
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "WEBSERVER_TECHNOLOGY",
            "WEBSERVER_BANNER",
        ]

    def producedEvents(self):
        return [
            "VULNERABILITY_GENERAL",
            "RAW_RIR_DATA",
        ]

    def queryCVE(self, cve_id):
        """Look up a CVE by ID (free endpoint, no credits consumed)."""
        url = "https://vulners.com/api/v3/search/id/"

        headers = {}
        if self.opts["api_key"]:
            headers["X-Api-Key"] = self.opts["api_key"]

        payload = json.dumps({
            "id": cve_id,
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

        if res["code"] != "200":
            self.debug(f"Unexpected response code {res['code']} from Vulners")
            return None

        try:
            data = json.loads(res["content"])
            if data.get("result") != "OK":
                return None
            return data.get("data", {}).get("documents", {})
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing Vulners response: {e}")
            return None

    def querySoftware(self, software, version):
        """Audit a software version for known vulnerabilities."""
        if not self.opts["api_key"]:
            return None

        url = "https://vulners.com/api/v4/audit/software"

        headers = {"X-Api-Key": self.opts["api_key"]}

        payload = json.dumps({
            "software": [
                {"software": software, "version": version}
            ],
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
            self.debug("Vulners API key invalid or credits exhausted for audit endpoint")
            return None

        if res["code"] != "200":
            return None

        try:
            data = json.loads(res["content"])
            if data.get("result") != "OK":
                return None
            return data.get("data", {})
        except (ValueError, TypeError) as e:
            self.error(f"Error parsing Vulners response: {e}")
            return None

    def _extractCVE(self, text):
        """Extract CVE ID from event data text."""
        import re
        match = re.search(r"(CVE-\d{4}-\d{4,7})", text)
        return match.group(1) if match else None

    def _parseSoftwareVersion(self, banner):
        """Try to extract software name and version from a banner/technology string."""
        import re
        # Match patterns like "Apache/2.4.51", "nginx/1.21.3", "OpenSSH_8.9"
        match = re.match(r"^([a-zA-Z][a-zA-Z0-9_.-]*)[/_ ]v?(\d+\.\d+[\d.]*)", banner)
        if match:
            return match.group(1), match.group(2)
        return None, None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName.startswith("VULNERABILITY_CVE_"):
            cve_id = self._extractCVE(eventData)
            if not cve_id:
                return

            if cve_id in self.results:
                return
            self.results[cve_id] = True

            documents = self.queryCVE(cve_id)
            if not documents:
                return

            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(documents), self.__name__, event)
            self.notifyListeners(e)

            # Check for exploit availability
            for doc_id, doc in documents.items():
                if not isinstance(doc, dict):
                    continue

                bulletin_family = doc.get("bulletinFamily", "")
                if bulletin_family.lower() == "exploit":
                    descr = f"Vulners - Exploit Available for {cve_id}\n"
                    descr += f" - Title: {doc.get('title', 'N/A')}\n"
                    descr += f" - Type: {doc.get('type', 'N/A')}\n"
                    cvss_score = doc.get("cvss", {}).get("score", "N/A")
                    descr += f" - CVSS: {cvss_score}\n"
                    descr += f"<SFURL>{doc.get('href', 'https://vulners.com')}</SFURL>"

                    e = SpiderFootEvent("VULNERABILITY_GENERAL", descr, self.__name__, event)
                    self.notifyListeners(e)

        elif eventName in ["WEBSERVER_TECHNOLOGY", "WEBSERVER_BANNER"]:
            software, version = self._parseSoftwareVersion(eventData)
            if not software or not version:
                return

            sw_key = f"{software}:{version}"
            if sw_key in self.results:
                return
            self.results[sw_key] = True

            data = self.querySoftware(software, version)
            if not data:
                return

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return

            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
            self.notifyListeners(e)

            for vuln in vulns[:10]:  # Limit to top 10
                if isinstance(vuln, dict):
                    descr = f"Vulners - Vulnerability in {software} {version}\n"
                    descr += f" - CVE: {vuln.get('id', 'N/A')}\n"
                    descr += f" - Title: {vuln.get('title', 'N/A')}\n"
                    descr += f" - CVSS: {vuln.get('cvss', {}).get('score', 'N/A')}\n"
                    descr += f"<SFURL>{vuln.get('href', 'https://vulners.com')}</SFURL>"

                    e = SpiderFootEvent("VULNERABILITY_GENERAL", descr, self.__name__, event)
                    self.notifyListeners(e)


# End of sfp_vulners class
