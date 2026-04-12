#  -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sflib
# Purpose:      Common functions used by SpiderFoot modules.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     26/03/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     MIT
# -------------------------------------------------------------------------------

import hashlib
import inspect
import io
import json
import logging
import os
import re
import sys
import time
import urllib.parse
from copy import deepcopy

import dns.resolver
import requests
import urllib3
from spiderfoot import SpiderFootHelpers
from spiderfoot.net.http import SpiderFootHttp
from spiderfoot.net.dns import SpiderFootDns
from spiderfoot.net.ssl import SpiderFootSsl
from spiderfoot.net import host as hostutil

# For hiding the SSL warnings coming from the requests lib
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # noqa: DUO131


class SpiderFoot:
    """SpiderFoot

    Attributes:
        dbh (SpiderFootDb): database handle
        scanId (str): scan ID this instance of SpiderFoot is being used in
        socksProxy (str): SOCKS proxy
        opts (dict): configuration options
    """
    _dbh = None
    _scanId = None
    _socksProxy = None
    opts = dict()

    def __init__(self, options: dict) -> None:
        """Initialize SpiderFoot object.

        Args:
            options (dict): dictionary of configuration options.

        Raises:
            TypeError: options argument was invalid type
        """
        if not isinstance(options, dict):
            raise TypeError(f"options is {type(options)}; expected dict()")

        self.opts = deepcopy(options)
        self.log = logging.getLogger(f"spiderfoot.{__name__}")

        if self.opts.get('_dnsserver', "") != "":
            res = dns.resolver.Resolver()
            res.nameservers = [self.opts['_dnsserver']]
            dns.resolver.override_system_resolver(res)

        # Instantiate extracted modules
        self._http = SpiderFootHttp(self.opts, self.log)
        self._dns = SpiderFootDns(self.opts, self.log)
        self._ssl = SpiderFootSsl(self.log)

    @property
    def dbh(self):
        """Database handle

        Returns:
            SpiderFootDb: database handle
        """
        return self._dbh

    @property
    def scanId(self) -> str:
        """Scan instance ID

        Returns:
            str: scan instance ID
        """
        return self._scanId

    @property
    def socksProxy(self) -> str:
        """SOCKS proxy

        Returns:
            str: socks proxy
        """
        return self._socksProxy

    @dbh.setter
    def dbh(self, dbh):
        """Called usually some time after instantiation
        to set up a database handle and scan ID, used
        for logging events to the database about a scan.

        Args:
            dbh (SpiderFootDb): database handle
        """
        self._dbh = dbh

    @scanId.setter
    def scanId(self, scanId: str) -> str:
        """Set the scan ID this instance of SpiderFoot is being used in.

        Args:
            scanId (str): scan instance ID
        """
        self._scanId = scanId

    @socksProxy.setter
    def socksProxy(self, socksProxy: str) -> str:
        """SOCKS proxy

        Bit of a hack to support SOCKS because of the loading order of
        modules. sfscan will call this to update the socket reference
        to the SOCKS one.

        Args:
            socksProxy (str): SOCKS proxy
        """
        self._socksProxy = socksProxy
        # Keep the HTTP client in sync
        self._http.socksProxy = socksProxy

    def optValueToData(self, val: str) -> str:
        """Supplied an option value, return the data based on what the
        value is. If val is a URL, you'll get back the fetched content,
        if val is a file path it will be loaded and get back the contents,
        and if a string it will simply be returned back.

        Args:
            val (str): option name

        Returns:
            str: option data
        """
        if not isinstance(val, str):
            self.error(f"Invalid option value {val}")
            return None

        if val.startswith('@'):
            fname = val.split('@')[1]
            self.info(f"Loading configuration data from: {fname}")

            try:
                with open(fname, "r") as f:
                    return f.read()
            except Exception as e:
                self.error(f"Unable to open option file, {fname}: {e}")
                return None

        if val.lower().startswith('http://') or val.lower().startswith('https://'):
            try:
                self.info(f"Downloading configuration data from: {val}")
                session = self.getSession()
                res = session.get(val)

                return res.content.decode('utf-8')
            except BaseException as e:
                self.error(f"Unable to open option URL, {val}: {e}")
                return None

        return val

    def error(self, message: str) -> None:
        """Print and log an error message

        Args:
            message (str): error message
        """
        if not self.opts['__logging']:
            return

        self.log.error(message, extra={'scanId': self._scanId})

    def fatal(self, error: str) -> None:
        """Print an error message and stacktrace then exit.

        Args:
            error (str): error message
        """
        self.log.critical(error, extra={'scanId': self._scanId})

        print(str(inspect.stack()))

        sys.exit(-1)

    def status(self, message: str) -> None:
        """Log and print a status message.

        Args:
            message (str): status message
        """
        if not self.opts['__logging']:
            return

        self.log.info(message, extra={'scanId': self._scanId})

    def info(self, message: str) -> None:
        """Log and print an info message.

        Args:
            message (str): info message
        """
        if not self.opts['__logging']:
            return

        self.log.info(f"{message}", extra={'scanId': self._scanId})

    def debug(self, message: str) -> None:
        """Log and print a debug message.

        Args:
            message (str): debug message
        """
        if not self.opts['_debug']:
            return
        if not self.opts['__logging']:
            return

        self.log.debug(f"{message}", extra={'scanId': self._scanId})

    def hashstring(self, string: str) -> str:
        """Returns a SHA256 hash of the specified input.

        Args:
            string (str): data to be hashed

        Returns:
            str: SHA256 hash
        """
        s = string
        if type(string) in [list, dict]:
            s = str(string)
        return hashlib.sha256(s.encode('raw_unicode_escape')).hexdigest()

    def cachePut(self, label: str, data: str) -> None:
        """Store data to the cache.

        Args:
            label (str): Name of the cached data to be used when retrieving the cached data.
            data (str): Data to cache
        """
        pathLabel = hashlib.sha224(label.encode('utf-8')).hexdigest()
        cacheFile = SpiderFootHelpers.cachePath() + "/" + pathLabel
        with io.open(cacheFile, "w", encoding="utf-8", errors="ignore") as fp:
            if isinstance(data, list):
                for line in data:
                    if isinstance(line, str):
                        fp.write(line)
                        fp.write("\n")
                    else:
                        fp.write(line.decode('utf-8') + '\n')
            elif isinstance(data, bytes):
                fp.write(data.decode('utf-8'))
            else:
                fp.write(data)

    def cacheGet(self, label: str, timeoutHrs: int) -> str:
        """Retreive data from the cache.

        Args:
            label (str): Name of the cached data to retrieve
            timeoutHrs (int): Age of the cached data (in hours)
                              for which the data is considered to be too old and ignored.

        Returns:
            str: cached data
        """
        if not label:
            return None

        pathLabel = hashlib.sha224(label.encode('utf-8')).hexdigest()
        cacheFile = SpiderFootHelpers.cachePath() + "/" + pathLabel
        try:
            cache_stat = os.stat(cacheFile)
        except OSError:
            return None

        if cache_stat.st_size == 0:
            return None

        if cache_stat.st_mtime > time.time() - timeoutHrs * 3600 or timeoutHrs == 0:
            with open(cacheFile, "r", encoding='utf-8') as fp:
                return fp.read()

        return None

    def configSerialize(self, opts: dict, filterSystem: bool = True):
        """Convert a Python dictionary to something storable in the database.

        Args:
            opts (dict): Dictionary of SpiderFoot configuration options
            filterSystem (bool): TBD

        Returns:
            dict: config options

        Raises:
            TypeError: arg type was invalid
        """
        if not isinstance(opts, dict):
            raise TypeError(f"opts is {type(opts)}; expected dict()")

        storeopts = dict()

        if not opts:
            return storeopts

        for opt in list(opts.keys()):
            # Filter out system temporary variables like GUID and others
            if opt.startswith('__') and filterSystem:
                continue

            if isinstance(opts[opt], (int, str)):
                storeopts[opt] = opts[opt]

            if isinstance(opts[opt], bool):
                if opts[opt]:
                    storeopts[opt] = 1
                else:
                    storeopts[opt] = 0
            if isinstance(opts[opt], list):
                storeopts[opt] = ','.join(opts[opt])

        if '__modules__' not in opts:
            return storeopts

        if not isinstance(opts['__modules__'], dict):
            raise TypeError(f"opts['__modules__'] is {type(opts['__modules__'])}; expected dict()")

        for mod in opts['__modules__']:
            for opt in opts['__modules__'][mod]['opts']:
                if opt.startswith('_') and filterSystem:
                    continue

                mod_opt = f"{mod}:{opt}"
                mod_opt_val = opts['__modules__'][mod]['opts'][opt]

                if isinstance(mod_opt_val, (int, str)):
                    storeopts[mod_opt] = mod_opt_val

                if isinstance(mod_opt_val, bool):
                    if mod_opt_val:
                        storeopts[mod_opt] = 1
                    else:
                        storeopts[mod_opt] = 0
                if isinstance(mod_opt_val, list):
                    storeopts[mod_opt] = ','.join(str(x) for x in mod_opt_val)

        return storeopts

    def configUnserialize(self, opts: dict, referencePoint: dict, filterSystem: bool = True):
        """Take strings, etc. from the database or UI and convert them
        to a dictionary for Python to process.

        Args:
            opts (dict): SpiderFoot configuration options
            referencePoint (dict): needed to know the actual types the options are supposed to be.
            filterSystem (bool): Ignore global "system" configuration options

        Returns:
            dict: TBD

        Raises:
            TypeError: arg type was invalid
        """

        if not isinstance(opts, dict):
            raise TypeError(f"opts is {type(opts)}; expected dict()")
        if not isinstance(referencePoint, dict):
            raise TypeError(f"referencePoint is {type(referencePoint)}; expected dict()")

        returnOpts = referencePoint

        # Global options
        for opt in list(referencePoint.keys()):
            if opt.startswith('__') and filterSystem:
                # Leave out system variables
                continue

            if opt not in opts:
                continue

            if isinstance(referencePoint[opt], bool):
                if opts[opt] == "1":
                    returnOpts[opt] = True
                else:
                    returnOpts[opt] = False
                continue

            if isinstance(referencePoint[opt], str):
                returnOpts[opt] = str(opts[opt])
                continue

            if isinstance(referencePoint[opt], int):
                returnOpts[opt] = int(opts[opt])
                continue

            if isinstance(referencePoint[opt], list):
                if isinstance(referencePoint[opt][0], int):
                    returnOpts[opt] = list()
                    for x in str(opts[opt]).split(","):
                        returnOpts[opt].append(int(x))
                else:
                    returnOpts[opt] = str(opts[opt]).split(",")

        if '__modules__' not in referencePoint:
            return returnOpts

        if not isinstance(referencePoint['__modules__'], dict):
            raise TypeError(f"referencePoint['__modules__'] is {type(referencePoint['__modules__'])}; expected dict()")

        # Module options
        # A lot of mess to handle typing..
        for modName in referencePoint['__modules__']:
            for opt in referencePoint['__modules__'][modName]['opts']:
                if opt.startswith('_') and filterSystem:
                    continue

                if modName + ":" + opt in opts:
                    ref_mod = referencePoint['__modules__'][modName]['opts'][opt]
                    if isinstance(ref_mod, bool):
                        if opts[modName + ":" + opt] == "1":
                            returnOpts['__modules__'][modName]['opts'][opt] = True
                        else:
                            returnOpts['__modules__'][modName]['opts'][opt] = False
                        continue

                    if isinstance(ref_mod, str):
                        returnOpts['__modules__'][modName]['opts'][opt] = str(opts[modName + ":" + opt])
                        continue

                    if isinstance(ref_mod, int):
                        returnOpts['__modules__'][modName]['opts'][opt] = int(opts[modName + ":" + opt])
                        continue

                    if isinstance(ref_mod, list):
                        if isinstance(ref_mod[0], int):
                            returnOpts['__modules__'][modName]['opts'][opt] = list()
                            for x in str(opts[modName + ":" + opt]).split(","):
                                returnOpts['__modules__'][modName]['opts'][opt].append(int(x))
                        else:
                            returnOpts['__modules__'][modName]['opts'][opt] = str(opts[modName + ":" + opt]).split(",")

        return returnOpts

    def modulesProducing(self, events: list) -> list:
        """Return an array of modules that produce the list of types supplied.

        Args:
            events (list): list of event types

        Returns:
            list: list of modules
        """
        modlist = list()

        if not events:
            return modlist

        loaded_modules = self.opts.get('__modules__')

        if not loaded_modules:
            return modlist

        for mod in list(loaded_modules.keys()):
            provides = loaded_modules[mod].get('provides')

            if not provides:
                continue

            if "*" in events:
                modlist.append(mod)

            for evtype in provides:
                if evtype in events:
                    modlist.append(mod)

        return list(set(modlist))

    def modulesConsuming(self, events: list) -> list:
        """Return an array of modules that consume the list of types supplied.

        Args:
            events (list): list of event types

        Returns:
            list: list of modules
        """
        modlist = list()

        if not events:
            return modlist

        loaded_modules = self.opts.get('__modules__')

        if not loaded_modules:
            return modlist

        for mod in list(loaded_modules.keys()):
            consumes = loaded_modules[mod].get('consumes')

            if not consumes:
                continue

            if "*" in consumes:
                modlist.append(mod)
                continue

            for evtype in consumes:
                if evtype in events:
                    modlist.append(mod)

        return list(set(modlist))

    def eventsFromModules(self, modules: list) -> list:
        """Return an array of types that are produced by the list of modules supplied.

        Args:
            modules (list): list of modules

        Returns:
            list: list of types
        """
        evtlist = list()

        if not modules:
            return evtlist

        loaded_modules = self.opts.get('__modules__')

        if not loaded_modules:
            return evtlist

        for mod in modules:
            if mod in list(loaded_modules.keys()):
                provides = loaded_modules[mod].get('provides')
                if provides:
                    for evt in provides:
                        evtlist.append(evt)

        return evtlist

    def eventsToModules(self, modules: list) -> list:
        """Return an array of types that are consumed by the list of modules supplied.

        Args:
            modules (list): list of modules

        Returns:
            list: list of types
        """
        evtlist = list()

        if not modules:
            return evtlist

        loaded_modules = self.opts.get('__modules__')

        if not loaded_modules:
            return evtlist

        for mod in modules:
            if mod in list(loaded_modules.keys()):
                consumes = loaded_modules[mod].get('consumes')
                if consumes:
                    for evt in consumes:
                        evtlist.append(evt)

        return evtlist

    # -----------------------------------------------------------------------
    # Delegation to spiderfoot.net.host (standalone functions)
    # -----------------------------------------------------------------------

    def urlFQDN(self, url: str) -> str:
        """Extract the FQDN from a URL."""
        if not url:
            self.error(f"Invalid URL: {url}")
            return None
        return hostutil.urlFQDN(url)

    def domainKeyword(self, domain: str, tldList: list) -> str:
        """Extract the keyword from a domain."""
        if not domain:
            self.error(f"Invalid domain: {domain}")
            return None
        return hostutil.domainKeyword(domain, tldList)

    def domainKeywords(self, domainList: list, tldList: list) -> set:
        """Extract keywords from a list of domains."""
        if not domainList:
            self.error(f"Invalid domain list: {domainList}")
            return set()
        result = hostutil.domainKeywords(domainList, tldList)
        self.debug(f"Keywords: {result}")
        return result

    def hostDomain(self, hostname: str, tldList: list) -> str:
        """Obtain the domain name for a supplied hostname."""
        return hostutil.hostDomain(hostname, tldList)

    def validHost(self, hostname: str, tldList: str) -> bool:
        """Check if the provided string is a valid hostname."""
        return hostutil.validHost(hostname, tldList)

    def isDomain(self, hostname: str, tldList: list) -> bool:
        """Check if the provided hostname string is a valid domain name."""
        return hostutil.isDomain(hostname, tldList)

    def validIP(self, address: str) -> bool:
        """Check if the provided string is a valid IPv4 address."""
        return hostutil.validIP(address)

    def validIP6(self, address: str) -> bool:
        """Check if the provided string is a valid IPv6 address."""
        return hostutil.validIP6(address)

    def validIpNetwork(self, cidr: str) -> bool:
        """Check if the provided string is a valid CIDR netblock."""
        return hostutil.validIpNetwork(cidr)

    def isPublicIpAddress(self, ip: str) -> bool:
        """Check if an IP address is public."""
        return hostutil.isPublicIpAddress(ip)

    # -----------------------------------------------------------------------
    # Delegation to spiderfoot.net.http (SpiderFootHttp)
    # -----------------------------------------------------------------------

    def fetchUrl(self, *args, **kwargs):
        """Fetch a URL and return the HTTP response as a dictionary."""
        return self._http.fetchUrl(*args, **kwargs)

    def getSession(self) -> 'requests.sessions.Session':
        """Return requests session object."""
        return self._http.getSession()

    def removeUrlCreds(self, url: str) -> str:
        """Remove potentially sensitive strings from a URL."""
        return self._http.removeUrlCreds(url)

    def isValidLocalOrLoopbackIp(self, ip: str) -> bool:
        """Check if IP address is local or loopback."""
        return self._http.isValidLocalOrLoopbackIp(ip)

    def useProxyForUrl(self, url: str) -> bool:
        """Check if the configured proxy should be used for a URL."""
        return self._http.useProxyForUrl(url)

    # -----------------------------------------------------------------------
    # Delegation to spiderfoot.net.dns (SpiderFootDns)
    # -----------------------------------------------------------------------

    def normalizeDNS(self, res: list) -> list:
        """Clean DNS results to be a simple list."""
        return self._dns.normalizeDNS(res)

    def resolveHost(self, host: str) -> list:
        """Return a normalised IPv4 resolution of a hostname."""
        return self._dns.resolveHost(host)

    def resolveIP(self, ipaddr: str) -> list:
        """Return a normalised resolution of an IPv4 or IPv6 address."""
        return self._dns.resolveIP(ipaddr)

    def resolveHost6(self, hostname: str) -> list:
        """Return a normalised IPv6 resolution of a hostname."""
        return self._dns.resolveHost6(hostname)

    def validateIP(self, host: str, ip: str) -> bool:
        """Verify a host resolves to a given IP."""
        return self._dns.validateIP(host, ip)

    def checkDnsWildcard(self, target: str) -> bool:
        """Check if wildcard DNS is enabled for a domain."""
        return self._dns.checkDnsWildcard(target)

    # -----------------------------------------------------------------------
    # Delegation to spiderfoot.net.ssl (SpiderFootSsl)
    # -----------------------------------------------------------------------

    def safeSocket(self, host: str, port: int, timeout: int) -> 'object':
        """Create a safe socket."""
        return self._ssl.safeSocket(host, port, timeout)

    def safeSSLSocket(self, host: str, port: int, timeout: int) -> 'object':
        """Create a safe SSL connection."""
        return self._ssl.safeSSLSocket(host, port, timeout)

    def parseCert(self, rawcert: str, fqdn: str = None, expiringdays: int = 30) -> dict:
        """Parse a PEM-format SSL certificate."""
        return self._ssl.parseCert(rawcert, fqdn, expiringdays)

    # -----------------------------------------------------------------------
    # Methods that remain in the facade (they call fetchUrl via delegation)
    # -----------------------------------------------------------------------

    def cveInfo(self, cveId: str, sources: str = "circl,nist") -> (str, str):
        """Look up a CVE ID for more information in the first available source.

        Args:
            cveId (str): CVE ID, e.g. CVE-2018-15473
            sources (str): Comma-separated list of sources to query. Options available are circl and nist

        Returns:
            (str, str): Appropriate event type and descriptive text
        """
        sources = sources.split(",")
        # VULNERABILITY_GENERAL is the generic type in case we don't have
        # a real/mappable CVE.
        eventType = "VULNERABILITY_GENERAL"

        def cveRating(score: int) -> str:
            if score == "Unknown":
                return None
            if score >= 0 and score <= 3.9:
                return "LOW"
            if score >= 4.0 and score <= 6.9:
                return "MEDIUM"
            if score >= 7.0 and score <= 8.9:
                return "HIGH"
            if score >= 9.0:
                return "CRITICAL"
            return None

        for source in sources:
            jsondata = self.cacheGet(f"{source}-{cveId}", 86400)

            if not jsondata:
                # Fetch data from source
                if source == "nist":
                    ret = self.fetchUrl(f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cveId}", timeout=5)
                if source == "circl":
                    ret = self.fetchUrl(f"https://cve.circl.lu/api/cve/{cveId}", timeout=5)

                if not ret:
                    continue

                if not ret['content']:
                    continue

                self.cachePut(f"{source}-{cveId}", ret['content'])
                jsondata = ret['content']

            try:
                data = json.loads(jsondata)

                if source == "circl":
                    score = data.get('cvss', 'Unknown')
                    rating = cveRating(score)
                    if rating:
                        eventType = f"VULNERABILITY_CVE_{rating}"
                        return (eventType, f"{cveId}\n<SFURL>https://nvd.nist.gov/vuln/detail/{cveId}</SFURL>\n"
                                f"Score: {score}\nDescription: {data.get('summary', 'Unknown')}")

                if source == "nist":
                    try:
                        if data['result']['CVE_Items'][0]['impact'].get('baseMetricV3'):
                            score = data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
                        else:
                            score = data['result']['CVE_Items'][0]['impact']['baseMetricV2']['cvssV2']['baseScore']
                        rating = cveRating(score)
                        if rating:
                            eventType = f"VULNERABILITY_CVE_{rating}"
                    except Exception:
                        score = "Unknown"

                    try:
                        descr = data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
                    except Exception:
                        descr = "Unknown"

                    return (eventType, f"{cveId}\n<SFURL>https://nvd.nist.gov/vuln/detail/{cveId}</SFURL>\n"
                            f"Score: {score}\nDescription: {descr}")
            except BaseException as e:
                self.debug(f"Unable to parse CVE response from {source.upper()}: {e}")
                continue

        return (eventType, f"{cveId}\nScore: Unknown\nDescription: Unknown")

    def googleIterate(self, searchString: str, opts: dict = None) -> dict:
        """Request search results from the Google API.

        Will return a dict:
        {
          "urls": a list of urls that match the query string,
          "webSearchUrl": url for Google results page,
        }

        Options accepted:
            useragent: User-Agent string to use
            timeout: API call timeout

        Args:
            searchString (str): Google search query
            opts (dict): TBD

        Returns:
            dict: Search results as {"webSearchUrl": "URL", "urls": [results]}
        """
        if not searchString:
            return None

        if opts is None:
            opts = {}

        search_string = searchString.replace(" ", "%20")
        params = urllib.parse.urlencode({
            "cx": opts["cse_id"],
            "key": opts["api_key"],
        })

        response = self.fetchUrl(
            f"https://www.googleapis.com/customsearch/v1?q={search_string}&{params}",
            timeout=opts["timeout"],
        )

        if response['code'] != '200':
            self.error("Failed to get a valid response from the Google API")
            return None

        try:
            response_json = json.loads(response['content'])
        except ValueError:
            self.error("The key 'content' in the Google API response doesn't contain valid JSON.")
            return None

        if "items" not in response_json:
            return None

        # We attempt to make the URL params look as authentically human as possible
        params = urllib.parse.urlencode({
            "ie": "utf-8",
            "oe": "utf-8",
            "aq": "t",
            "rls": "org.mozilla:en-US:official",
            "client": "firefox-a",
        })

        return {
            "urls": [str(k['link']) for k in response_json['items']],
            "webSearchUrl": f"https://www.google.com/search?q={search_string}&{params}"
        }

    def bingIterate(self, searchString: str, opts: dict = None) -> dict:
        """Request search results from the Bing API.

        Will return a dict:
        {
          "urls": a list of urls that match the query string,
          "webSearchUrl": url for bing results page,
        }

        Options accepted:
            count: number of search results to request from the API
            useragent: User-Agent string to use
            timeout: API call timeout

        Args:
            searchString (str): Bing search query
            opts (dict): TBD

        Returns:
            dict: Search results as {"webSearchUrl": "URL", "urls": [results]}
        """
        if not searchString:
            return None

        if opts is None:
            opts = {}

        search_string = searchString.replace(" ", "%20")
        params = urllib.parse.urlencode({
            "responseFilter": "Webpages",
            "count": opts["count"],
        })

        response = self.fetchUrl(
            f"https://api.cognitive.microsoft.com/bing/v7.0/search?q={search_string}&{params}",
            timeout=opts["timeout"],
            useragent=opts["useragent"],
            headers={"Ocp-Apim-Subscription-Key": opts["api_key"]},
        )

        if response['code'] != '200':
            self.error("Failed to get a valid response from the Bing API")
            return None

        try:
            response_json = json.loads(response['content'])
        except ValueError:
            self.error("The key 'content' in the bing API response doesn't contain valid JSON.")
            return None

        if ("webPages" in response_json and "value" in response_json["webPages"] and "webSearchUrl" in response_json["webPages"]):
            return {
                "urls": [result["url"] for result in response_json["webPages"]["value"]],
                "webSearchUrl": response_json["webPages"]["webSearchUrl"],
            }

        return None

# end of SpiderFoot class
