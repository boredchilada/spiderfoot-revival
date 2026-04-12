# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.net.host
# Purpose:      Pure utility functions for hostname/IP/domain validation and parsing.
#               Extracted from sflib.SpiderFoot as part of the god-object decomposition.
#
# Original author: Steve Micallef <steve@binarypool.com>
# -------------------------------------------------------------------------------

import re

import netaddr
from publicsuffixlist import PublicSuffixList
from spiderfoot import SpiderFootHelpers


def urlFQDN(url: str) -> str:
    """Extract the FQDN from a URL.

    Args:
        url (str): URL

    Returns:
        str: FQDN
    """
    if not url:
        return None

    baseurl = SpiderFootHelpers.urlBaseUrl(url)
    if '://' in baseurl:
        count = 2
    else:
        count = 0

    # http://abc.com will split to ['http:', '', 'abc.com']
    return baseurl.split('/')[count].lower()


def domainKeyword(domain: str, tldList: list) -> str:
    """Extract the keyword (the domain without the TLD or any subdomains) from a domain.

    Args:
        domain (str): The domain to check.
        tldList (list): The list of TLDs based on the Mozilla public list.

    Returns:
        str: The keyword
    """
    if not domain:
        return None

    # Strip off the TLD
    dom = hostDomain(domain.lower(), tldList)
    if not dom:
        return None

    tld = '.'.join(dom.split('.')[1:])
    ret = domain.lower().replace('.' + tld, '')

    # If the user supplied a domain with a sub-domain, return the second part
    if '.' in ret:
        return ret.split('.')[-1]

    return ret


def domainKeywords(domainList: list, tldList: list) -> set:
    """Extract the keywords (the domains without the TLD or any subdomains) from a list of domains.

    Args:
        domainList (list): The list of domains to check.
        tldList (list): The list of TLDs based on the Mozilla public list.

    Returns:
        set: List of keywords
    """
    if not domainList:
        return set()

    keywords = list()
    for domain in domainList:
        keywords.append(domainKeyword(domain, tldList))

    return set([k for k in keywords if k])


def hostDomain(hostname: str, tldList: list) -> str:
    """Obtain the domain name for a supplied hostname.

    Args:
        hostname (str): The hostname to check.
        tldList (list): The list of TLDs based on the Mozilla public list.

    Returns:
        str: The domain name.
    """
    if not tldList:
        return None
    if not hostname:
        return None

    ps = PublicSuffixList(tldList, only_icann=True)
    return ps.privatesuffix(hostname)


def validHost(hostname: str, tldList: str) -> bool:
    """Check if the provided string is a valid hostname with a valid public suffix TLD.

    Args:
        hostname (str): The hostname to check.
        tldList (str): The list of TLDs based on the Mozilla public list.

    Returns:
        bool
    """
    if not tldList:
        return False
    if not hostname:
        return False

    if "." not in hostname:
        return False

    if not re.match(r"^[a-z0-9-\.]*$", hostname, re.IGNORECASE):
        return False

    ps = PublicSuffixList(tldList, only_icann=True, accept_unknown=False)
    sfx = ps.privatesuffix(hostname)
    return sfx is not None


def isDomain(hostname: str, tldList: list) -> bool:
    """Check if the provided hostname string is a valid domain name.

    Given a possible hostname, check if it's a domain name
    By checking whether it rests atop a valid TLD.
    e.g. www.example.com = False because tld of hostname is com,
    and www.example has a . in it.

    Args:
        hostname (str): The hostname to check.
        tldList (list): The list of TLDs based on the Mozilla public list.

    Returns:
        bool
    """
    if not tldList:
        return False
    if not hostname:
        return False

    ps = PublicSuffixList(tldList, only_icann=True, accept_unknown=False)
    sfx = ps.privatesuffix(hostname)
    return sfx == hostname


def validIP(address: str) -> bool:
    """Check if the provided string is a valid IPv4 address.

    Args:
        address (str): The IPv4 address to check.

    Returns:
        bool
    """
    if not address:
        return False
    return netaddr.valid_ipv4(address)


def validIP6(address: str) -> bool:
    """Check if the provided string is a valid IPv6 address.

    Args:
        address (str): The IPv6 address to check.

    Returns:
        bool: string is a valid IPv6 address
    """
    if not address:
        return False
    return netaddr.valid_ipv6(address)


def validIpNetwork(cidr: str) -> bool:
    """Check if the provided string is a valid CIDR netblock.

    Args:
        cidr (str): The netblock to check.

    Returns:
        bool: string is a valid CIDR netblock
    """
    if not isinstance(cidr, str):
        return False

    if '/' not in cidr:
        return False

    try:
        return netaddr.IPNetwork(str(cidr)).size > 0
    except BaseException:
        return False


def isPublicIpAddress(ip: str) -> bool:
    """Check if an IP address is public.

    Args:
        ip (str): IP address

    Returns:
        bool: IP address is public
    """
    if not isinstance(ip, (str, netaddr.IPAddress)):
        return False
    if not validIP(ip) and not validIP6(ip):
        return False

    if not netaddr.IPAddress(ip).is_unicast():
        return False

    if netaddr.IPAddress(ip).is_loopback():
        return False
    if netaddr.IPAddress(ip).is_reserved():
        return False
    if netaddr.IPAddress(ip).is_multicast():
        return False
    if netaddr.IPAddress(ip).is_private():
        return False
    return True
