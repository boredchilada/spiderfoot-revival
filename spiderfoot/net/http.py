# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.net.http
# Purpose:      HTTP client functionality extracted from sflib.SpiderFoot.
#
# Original author: Steve Micallef <steve@binarypool.com>
# -------------------------------------------------------------------------------

import logging
import random
import re
import time
import urllib.parse

import netaddr
import requests
import urllib3

from spiderfoot import SpiderFootHelpers
from spiderfoot.net import host as hostutil

# For hiding the SSL warnings coming from the requests lib
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # noqa: DUO131


class SpiderFootHttp:
    """HTTP client extracted from SpiderFoot.

    Attributes:
        opts (dict): configuration options
        log (logging.Logger): logger instance
        socksProxy (str): SOCKS proxy URL
    """

    def __init__(self, opts: dict, logger: logging.Logger) -> None:
        self.opts = opts
        self.log = logger
        self.socksProxy = None

    def getSession(self) -> 'requests.sessions.Session':
        """Return requests session object.

        Returns:
            requests.sessions.Session: requests session
        """
        session = requests.session()
        if self.socksProxy:
            session.proxies = {
                'http': self.socksProxy,
                'https': self.socksProxy,
            }
        return session

    def removeUrlCreds(self, url: str) -> str:
        """Remove potentially sensitive strings (such as "key=..." and "password=...") from a string.

        Used to remove potential credentials from URLs prior during logging.

        Args:
            url (str): URL

        Returns:
            str: Sanitized URL
        """
        pats = {
            r'key=\S+': "key=XXX",
            r'pass=\S+': "pass=XXX",
            r'user=\S+': "user=XXX",
            r'password=\S+': "password=XXX",
            r'token=\S+': "token=XXX",
            r'secret=\S+': "secret=XXX",
            r'apikey=\S+': "apikey=XXX",
            r'api_key=\S+': "api_key=XXX",
            r'access_token=\S+': "access_token=XXX",
        }

        ret = url
        for pat in pats:
            ret = re.sub(pat, pats[pat], ret, flags=re.IGNORECASE)

        return ret

    def isValidLocalOrLoopbackIp(self, ip: str) -> bool:
        """Check if the specified IPv4 or IPv6 address is a loopback or local network IP address.

        Args:
            ip (str): IPv4 or IPv6 address

        Returns:
            bool: IP address is local or loopback
        """
        if not hostutil.validIP(ip) and not hostutil.validIP6(ip):
            return False

        if netaddr.IPAddress(ip).is_private():
            return True

        if netaddr.IPAddress(ip).is_loopback():
            return True

        return False

    def useProxyForUrl(self, url: str) -> bool:
        """Check if the configured proxy should be used to connect to a specified URL.

        Args:
            url (str): The URL to check

        Returns:
            bool: should the configured proxy be used?
        """
        url_host = hostutil.urlFQDN(url)
        if url_host:
            url_host = url_host.lower()
        else:
            return False

        if not self.opts.get('_socks1type'):
            return False

        proxy_host = self.opts.get('_socks2addr')

        if not proxy_host:
            return False

        proxy_port = self.opts.get('_socks3port')

        if not proxy_port:
            return False

        # Never proxy requests to the proxy host
        if url_host == proxy_host.lower():
            return False

        # Never proxy RFC1918 addresses on the LAN or the local network interface
        if hostutil.validIP(url_host):
            if netaddr.IPAddress(url_host).is_private():
                return False
            if netaddr.IPAddress(url_host).is_loopback():
                return False

        # Never proxy local hostnames
        else:
            neverProxyNames = ['local', 'localhost']
            if url_host in neverProxyNames:
                return False

            for s in neverProxyNames:
                if url_host.endswith(s):
                    return False

        return True

    def fetchUrl(
        self,
        url: str,
        cookies: str = None,
        timeout: int = 30,
        useragent: str = "SpiderFoot",
        headers: dict = None,
        noLog: bool = False,
        postData: str = None,
        disableContentEncoding: bool = False,
        sizeLimit: int = None,
        headOnly: bool = False,
        verify: bool = True,
        _redirectDepth: int = 0
    ) -> dict:
        """Fetch a URL and return the HTTP response as a dictionary.

        Args:
            url (str): URL to fetch
            cookies (str): cookies
            timeout (int): timeout
            useragent (str): user agent header
            headers (dict): headers
            noLog (bool): do not log request
            postData (str): HTTP POST data
            disableContentEncoding (bool): do not UTF-8 encode response body
            sizeLimit (int): size threshold
            headOnly (bool): use HTTP HEAD method
            verify (bool): use HTTPS SSL/TLS verification

        Returns:
            dict: HTTP response
        """
        if not url:
            return None

        result = {
            'code': None,
            'status': None,
            'content': None,
            'headers': None,
            'realurl': url
        }

        url = url.strip()

        try:
            parsed_url = urllib.parse.urlparse(url)
        except Exception:
            self.log.debug(f"Could not parse URL: {url}")
            return None

        if parsed_url.scheme != 'http' and parsed_url.scheme != 'https':
            self.log.debug(f"Invalid URL scheme for URL: {url}")
            return None

        request_log = []

        proxies = dict()
        if self.useProxyForUrl(url):
            proxies = {
                'http': self.socksProxy,
                'https': self.socksProxy,
            }

        header = dict()
        btime = time.time()

        if isinstance(useragent, list):
            header['User-Agent'] = random.SystemRandom().choice(useragent)
        else:
            header['User-Agent'] = useragent

        # Add custom headers
        if isinstance(headers, dict):
            for k in list(headers.keys()):
                header[k] = str(headers[k])

        request_log.append(f"proxy={self.socksProxy}")
        request_log.append(f"user-agent={header['User-Agent']}")
        request_log.append(f"timeout={timeout}")
        request_log.append(f"cookies={cookies}")

        if sizeLimit or headOnly:
            if noLog:
                self.log.debug(f"Fetching (HEAD): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
            else:
                self.log.info(f"Fetching (HEAD): {self.removeUrlCreds(url)} ({', '.join(request_log)})")

            try:
                hdr = self.getSession().head(
                    url,
                    headers=header,
                    proxies=proxies,
                    verify=verify,
                    timeout=timeout
                )
            except Exception as e:
                if noLog:
                    self.log.debug(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {url}", exc_info=True)
                else:
                    self.log.error(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {url}", exc_info=True)

                return result

            size = int(hdr.headers.get('content-length', 0))
            newloc = hdr.headers.get('location', url).strip()

            # Relative re-direct
            if newloc.startswith("/") or newloc.startswith("../"):
                newloc = SpiderFootHelpers.urlBaseUrl(url) + newloc
            result['realurl'] = newloc
            result['code'] = str(hdr.status_code)

            if headOnly:
                return result

            if size > sizeLimit:
                return result

            if result['realurl'] != url:
                if noLog:
                    self.log.debug(f"Fetching (HEAD): {self.removeUrlCreds(result['realurl'])} ({', '.join(request_log)})")
                else:
                    self.log.info(f"Fetching (HEAD): {self.removeUrlCreds(result['realurl'])} ({', '.join(request_log)})")

                try:
                    hdr = self.getSession().head(
                        result['realurl'],
                        headers=header,
                        proxies=proxies,
                        verify=verify,
                        timeout=timeout
                    )
                    size = int(hdr.headers.get('content-length', 0))
                    result['realurl'] = hdr.headers.get('location', result['realurl'])
                    result['code'] = str(hdr.status_code)

                    if size > sizeLimit:
                        return result

                except Exception as e:
                    if noLog:
                        self.log.debug(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {result['realurl']}", exc_info=True)
                    else:
                        self.log.error(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {result['realurl']}", exc_info=True)

                    return result

        try:
            if postData:
                if noLog:
                    self.log.debug(f"Fetching (POST): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
                else:
                    self.log.info(f"Fetching (POST): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
                res = self.getSession().post(
                    url,
                    data=postData,
                    headers=header,
                    proxies=proxies,
                    allow_redirects=True,
                    cookies=cookies,
                    timeout=timeout,
                    verify=verify
                )
            else:
                if noLog:
                    self.log.debug(f"Fetching (GET): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
                else:
                    self.log.info(f"Fetching (GET): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
                res = self.getSession().get(
                    url,
                    headers=header,
                    proxies=proxies,
                    allow_redirects=True,
                    cookies=cookies,
                    timeout=timeout,
                    verify=verify
                )
        except requests.exceptions.RequestException as e:
            self.log.error(f"Failed to connect to {url}: {e}")
            return result
        except Exception as e:
            if noLog:
                self.log.debug(f"Unexpected exception ({e}) occurred fetching URL: {url}", exc_info=True)
            else:
                self.log.error(f"Unexpected exception ({e}) occurred fetching URL: {url}", exc_info=True)

            return result

        try:
            result['headers'] = dict()
            result['realurl'] = res.url
            result['code'] = str(res.status_code)

            for header, value in res.headers.items():
                result['headers'][str(header).lower()] = str(value)

            # Sometimes content exceeds the size limit after decompression
            if sizeLimit and len(res.content) > sizeLimit:
                self.log.debug(f"Content exceeded size limit ({sizeLimit}), so returning no data just headers")
                return result

            refresh_header = result['headers'].get('refresh')
            if refresh_header:
                try:
                    newurl = refresh_header.split(";url=")[1]
                except Exception as e:
                    self.log.debug(f"Refresh header '{refresh_header}' found, but not parsable: {e}")
                    return result

                self.log.debug(f"Refresh header '{refresh_header}' found, re-directing to {self.removeUrlCreds(newurl)}")

                if _redirectDepth >= 10:
                    self.log.debug("Max refresh redirects (10) reached, stopping")
                    return result

                return self.fetchUrl(
                    newurl,
                    cookies,
                    timeout,
                    useragent,
                    headers,
                    noLog,
                    postData,
                    disableContentEncoding,
                    sizeLimit,
                    headOnly,
                    _redirectDepth=_redirectDepth + 1
                )

            if disableContentEncoding:
                result['content'] = res.content
            else:
                for encoding in ("utf-8", "ascii"):
                    try:
                        result["content"] = res.content.decode(encoding)
                    except UnicodeDecodeError:
                        pass
                    else:
                        break
                else:
                    result["content"] = res.content

        except Exception as e:
            self.log.error(f"Unexpected exception ({e}) occurred parsing response for URL: {url}", exc_info=True)
            result['content'] = None
            result['status'] = str(e)

        atime = time.time()
        t = str(atime - btime)
        self.log.info(f"Fetched {self.removeUrlCreds(url)} ({len(result['content'] or '')} bytes in {t}s)")
        return result
