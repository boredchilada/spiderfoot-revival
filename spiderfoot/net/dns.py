# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.net.dns
# Purpose:      DNS resolution functionality extracted from sflib.SpiderFoot.
#
# Original author: Steve Micallef <steve@binarypool.com>
# -------------------------------------------------------------------------------

import logging
import random
import socket

from spiderfoot.net import host as hostutil


class SpiderFootDns:
    """DNS resolution extracted from SpiderFoot.

    Attributes:
        opts (dict): configuration options
        log (logging.Logger): logger instance
    """

    def __init__(self, opts: dict, logger: logging.Logger) -> None:
        self.opts = opts
        self.log = logger

    def normalizeDNS(self, res: list) -> list:
        """Clean DNS results to be a simple list

        Args:
            res (list): List of DNS names

        Returns:
            list: list of domains
        """
        ret = list()

        if not res:
            return ret

        for addr in res:
            if isinstance(addr, list):
                for host in addr:
                    host = str(host).rstrip(".")
                    if host:
                        ret.append(host)
            else:
                host = str(addr).rstrip(".")
                if host:
                    ret.append(host)
        return ret

    def resolveHost(self, host: str) -> list:
        """Return a normalised IPv4 resolution of a hostname.

        Args:
            host (str): host to resolve

        Returns:
            list: IP addresses
        """
        if not host:
            self.log.error(f"Unable to resolve host: {host} (Invalid host)")
            return list()

        addrs = list()
        try:
            addrs = self.normalizeDNS(socket.gethostbyname_ex(host))
        except BaseException as e:
            self.log.debug(f"Unable to resolve host: {host} ({e})")
            return addrs

        if not addrs:
            self.log.debug(f"Unable to resolve host: {host}")
            return addrs

        self.log.debug(f"Resolved {host} to IPv4: {addrs}")

        return list(set(addrs))

    def resolveIP(self, ipaddr: str) -> list:
        """Return a normalised resolution of an IPv4 or IPv6 address.

        Args:
            ipaddr (str): IP address to reverse resolve

        Returns:
            list: list of domain names
        """

        if not hostutil.validIP(ipaddr) and not hostutil.validIP6(ipaddr):
            self.log.error(f"Unable to reverse resolve {ipaddr} (Invalid IP address)")
            return list()

        self.log.debug(f"Performing reverse resolve of {ipaddr}")

        try:
            addrs = self.normalizeDNS(socket.gethostbyaddr(ipaddr))
        except BaseException as e:
            self.log.debug(f"Unable to reverse resolve IP address: {ipaddr} ({e})")
            return list()

        if not addrs:
            self.log.debug(f"Unable to reverse resolve IP address: {ipaddr}")
            return list()

        self.log.debug(f"Reverse resolved {ipaddr} to: {addrs}")

        return list(set(addrs))

    def resolveHost6(self, hostname: str) -> list:
        """Return a normalised IPv6 resolution of a hostname.

        Args:
            hostname (str): hostname to resolve

        Returns:
            list
        """
        if not hostname:
            self.log.error(f"Unable to resolve host: {hostname} (Invalid host)")
            return list()

        addrs = list()
        try:
            res = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            for addr in res:
                if addr[4][0] not in addrs:
                    addrs.append(addr[4][0])
        except BaseException as e:
            self.log.debug(f"Unable to resolve host: {hostname} ({e})")
            return addrs

        if not addrs:
            self.log.debug(f"Unable to resolve host: {hostname}")
            return addrs

        self.log.debug(f"Resolved {hostname} to IPv6: {addrs}")

        return list(set(addrs))

    def validateIP(self, host: str, ip: str) -> bool:
        """Verify a host resolves to a given IP.

        Args:
            host (str): host
            ip (str): IP address

        Returns:
            bool: host resolves to the given IP address
        """
        if not host:
            self.log.error(f"Unable to resolve host: {host} (Invalid host)")
            return False

        if hostutil.validIP(ip):
            addrs = self.resolveHost(host)
        elif hostutil.validIP6(ip):
            addrs = self.resolveHost6(host)
        else:
            self.log.error(f"Unable to verify hostname {host} resolves to {ip} (Invalid IP address)")
            return False

        if not addrs:
            return False

        return any(str(addr) == ip for addr in addrs)

    def checkDnsWildcard(self, target: str) -> bool:
        """Check if wildcard DNS is enabled for a domain by looking up a random subdomain.

        Args:
            target (str): domain

        Returns:
            bool: Domain returns DNS records for any subdomains
        """
        if not target:
            return False

        randpool = 'bcdfghjklmnpqrstvwxyz3456789'
        randhost = ''.join([random.SystemRandom().choice(randpool) for x in range(10)])

        if not self.resolveHost(randhost + "." + target):
            return False

        return True
