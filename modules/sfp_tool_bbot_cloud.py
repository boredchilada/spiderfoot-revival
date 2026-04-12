# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_bbot_cloud
# Purpose:      SpiderFoot plug-in for using BBOT for cloud and SaaS recon
#               (cloud buckets, Azure tenant, Docker Hub, Postman).
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

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_bbot_cloud(SpiderFootPlugin):

    meta = {
        "name": "Tool - BBOT Cloud Recon",
        "summary": "Use BBOT for cloud infrastructure recon: S3/Azure/GCP bucket discovery, Docker Hub, Postman workspace leaks, and Azure tenant enumeration.",
        "flags": ["tool", "slow"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "name": "BBOT",
            "description": "BBOT cloud recon modules discover misconfigured cloud storage buckets "
            "(AWS S3, Azure Blob, GCP, DigitalOcean, Firebase), public Docker Hub repositories, "
            "leaked Postman API collections, and Azure AD tenant information.",
            "website": "https://github.com/blacklanternsecurity/bbot",
            "repository": "https://github.com/blacklanternsecurity/bbot",
        },
    }

    opts = {
        "bbot_path": "",
        "modules": "bucket_amazon,bucket_google,bucket_microsoft,bucket_digitalocean,bucket_firebase,dockerhub,postman,azure_tenant",
        "timeout": 600,
    }

    optdescs = {
        "bbot_path": "Path to bbot binary. If empty, assumes 'bbot' is in PATH.",
        "modules": "Comma-separated list of BBOT cloud recon modules to enable.",
        "timeout": "Maximum scan time in seconds (default: 600).",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        self._mergeOpts(userOpts)

    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME"]

    def producedEvents(self):
        return [
            "CLOUD_STORAGE_BUCKET",
            "CLOUD_STORAGE_BUCKET_OPEN",
            "PUBLIC_CODE_REPO",
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
        ]

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            try:
                stdout, stderr = p.communicate(timeout=self.opts["timeout"])
                content = stdout.decode("utf-8", errors="replace")
            except TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                self.debug("BBOT cloud scan timed out")
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
            module = data.get("module", "")

            if not evt_data:
                continue

            if evt_type == "STORAGE_BUCKET":
                bucket_url = str(evt_data) if not isinstance(evt_data, dict) else evt_data.get("url", str(evt_data))
                e = SpiderFootEvent("CLOUD_STORAGE_BUCKET_OPEN", bucket_url, self.__name__, event)
                self.notifyListeners(e)

            elif evt_type == "CODE_REPOSITORY":
                repo_url = str(evt_data) if not isinstance(evt_data, dict) else evt_data.get("url", str(evt_data))
                e = SpiderFootEvent("PUBLIC_CODE_REPO", repo_url, self.__name__, event)
                self.notifyListeners(e)

            elif evt_type == "FINDING":
                if isinstance(evt_data, dict):
                    description = evt_data.get("description", str(evt_data))
                else:
                    description = str(evt_data)

                descr = f"BBOT Cloud Finding [{eventData}]\n"
                descr += f" - Details: {description}\n"
                descr += f" - Module: {module}"

                e = SpiderFootEvent("VULNERABILITY_GENERAL", descr, self.__name__, event)
                self.notifyListeners(e)

            if evt_type in ("STORAGE_BUCKET", "CODE_REPOSITORY", "FINDING"):
                e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
                self.notifyListeners(e)


# End of sfp_tool_bbot_cloud class
