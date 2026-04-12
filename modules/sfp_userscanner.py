# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_userscanner
# Purpose:      Check email registrations and username existence across 195+
#               platforms using the user-scanner library.
#               Tool: https://github.com/kaifcodec/user-scanner
#
# Author:       SpiderFoot Revival Project
#
# Created:      2026-04-08
# Copyright:    (c) SpiderFoot Revival Project
# Licence:      MIT
# -------------------------------------------------------------------------------

import asyncio
import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_userscanner(SpiderFootPlugin):

    meta = {
        "name": "User Scanner",
        "summary": "Check email registrations across 95+ sites and username existence across 100+ platforms using the user-scanner library.",
        "flags": ["slow"],
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Public Registries"],
        "dataSource": {
            "website": "https://github.com/kaifcodec/user-scanner",
            "model": "FREE_NOAUTH_UNLIMITED",
            "references": [
                "https://pypi.org/project/user-scanner/",
            ],
            "description": "User Scanner is a Python OSINT tool that checks email registrations "
            "across 95+ sites and username availability across 100+ platforms. It queries "
            "publicly accessible, unauthenticated web endpoints to identify digital footprints. "
            "Install via: pip install user-scanner",
        },
    }

    opts = {
        "categories": "",
        "max_platforms": 200,
    }

    optdescs = {
        "categories": "Comma-separated list of categories to scan (e.g., 'dev,social,gaming'). Empty = all.",
        "max_platforms": "Maximum number of platforms to check per target (default: 200).",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["EMAILADDR", "USERNAME"]

    def producedEvents(self):
        return [
            "ACCOUNT_EXTERNAL_OWNED",
            "SOCIAL_MEDIA",
            "RAW_RIR_DATA",
        ]

    def _runEmailScan(self, email):
        """Run user-scanner email check."""
        try:
            from user_scanner.core import engine
            from user_scanner.email_scan import modules as email_modules
        except ImportError:
            self.error("user-scanner library not installed. Run: pip install user-scanner")
            self.errorState = True
            return []

        results = []

        async def scan():
            checked = 0
            for module in dir(email_modules):
                if module.startswith("_"):
                    continue

                if checked >= self.opts["max_platforms"]:
                    break

                if self.checkForStop():
                    break

                mod = getattr(email_modules, module, None)
                if mod is None:
                    continue

                try:
                    result = await engine.check(mod, email)
                    if result and hasattr(result, "status"):
                        if result.status in ["Registered", "Found"]:
                            results.append({
                                "site": getattr(result, "site", module),
                                "url": getattr(result, "url", ""),
                                "status": result.status,
                            })
                    checked += 1
                except Exception:
                    continue

        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(scan())
            loop.close()
        except Exception as e:
            self.debug(f"Error running email scan: {e}")

        return results

    def _runUsernameScan(self, username):
        """Run user-scanner username check via CLI subprocess as fallback."""
        import subprocess

        try:
            args = ["user-scanner", "-u", username, "--json"]

            if self.opts.get("categories"):
                for cat in self.opts["categories"].split(","):
                    args.extend(["-c", cat.strip()])

            p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate(timeout=300)

            if not stdout:
                return []

            results = []
            content = stdout.decode("utf-8", errors="replace")
            for line in content.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    if data.get("status") in ["Found", "Registered"]:
                        results.append(data)
                except (ValueError, TypeError):
                    continue

            return results

        except FileNotFoundError:
            self.error("user-scanner CLI not found. Run: pip install user-scanner")
            self.errorState = True
            return []
        except subprocess.TimeoutExpired:
            self.debug("user-scanner timed out")
            return []
        except Exception as e:
            self.debug(f"Error running username scan: {e}")
            return []

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "EMAILADDR":
            results = self._runEmailScan(eventData)
        elif eventName == "USERNAME":
            results = self._runUsernameScan(eventData)
        else:
            return

        if not results:
            return

        e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(results), self.__name__, event)
        self.notifyListeners(e)

        for result in results:
            site = result.get("site", "Unknown")
            url = result.get("url", "")

            if url:
                social_media_platforms = [
                    "twitter", "instagram", "facebook", "tiktok", "reddit",
                    "linkedin", "pinterest", "tumblr", "snapchat", "discord",
                    "mastodon", "threads", "youtube", "twitch",
                ]
                is_social = any(p in site.lower() or p in url.lower() for p in social_media_platforms)

                if is_social:
                    descr = f"{site}: <SFURL>{url}</SFURL>"
                    e = SpiderFootEvent("SOCIAL_MEDIA", descr, self.__name__, event)
                else:
                    descr = f"{site}: <SFURL>{url}</SFURL>"
                    e = SpiderFootEvent("ACCOUNT_EXTERNAL_OWNED", descr, self.__name__, event)
                self.notifyListeners(e)
            else:
                descr = f"{site} [Account Registered]"
                e = SpiderFootEvent("ACCOUNT_EXTERNAL_OWNED", descr, self.__name__, event)
                self.notifyListeners(e)


# End of sfp_userscanner class
