"""Scan preset service.

Owns the built-in preset catalog, module-name validation, and idempotent
seeding of built-in presets into the database.
"""

import logging
from typing import Iterable

log = logging.getLogger(__name__)


BUILTIN_PRESETS = [
    # Metadata-derived: module list computed at seed time from each module's
    # `useCases` metadata. Adding a new module with useCases:[Footprint] joins
    # the Footprint preset on next startup.
    {'id': 'builtin:footprint',   'name': 'Footprint',
     'description': 'Discover public info about a target',
     'derive_from_usecase': 'Footprint',   'sort_order': 10},
    {'id': 'builtin:investigate', 'name': 'Investigate',
     'description': 'Deep recon including history',
     'derive_from_usecase': 'Investigate', 'sort_order': 20},
    {'id': 'builtin:passive',     'name': 'Passive',
     'description': 'Safe — no direct target contact',
     'derive_from_usecase': 'Passive',     'sort_order': 30},

    {'id': 'builtin:subdomain_enum', 'name': 'Subdomain enum', 'sort_order': 40,
     'description': 'Enumerate subdomains via DNS, certificate transparency, and search engines',
     'modules': [
         'sfp_dnsbrute', 'sfp_crt', 'sfp_certspotter', 'sfp_dnscommonsrv',
         'sfp_dnsneighbor', 'sfp_dnsraw', 'sfp_dnsresolve', 'sfp_dnsdumpster',
         'sfp_dnsdb', 'sfp_dnsgrep', 'sfp_dnszonexfer', 'sfp_subdomain_takeover',
         'sfp_hackertarget', 'sfp_virustotal', 'sfp_securitytrails', 'sfp_shodan',
         'sfp_bevigil', 'sfp_fullhunt',
     ]},

    {'id': 'builtin:email_investigation', 'name': 'Email investigation', 'sort_order': 50,
     'description': 'Breaches, social profiles, format guess for an email address',
     'modules': [
         'sfp_haveibeenpwned', 'sfp_emailrep', 'sfp_emailcrawlr', 'sfp_emailformat',
         'sfp_hunter', 'sfp_dehashed', 'sfp_intelx', 'sfp_skymem', 'sfp_pgp',
         'sfp_gravatar', 'sfp_fullcontact', 'sfp_debounce', 'sfp_psbdmp',
     ]},

    {'id': 'builtin:threat_intel', 'name': 'Threat intel', 'sort_order': 60,
     'description': 'Reputation and blocklist lookups across major threat-intel sources',
     'modules': [
         'sfp_alienvault', 'sfp_alienvaultiprep', 'sfp_abusech', 'sfp_abuseipdb',
         'sfp_greynoise', 'sfp_greynoise_community', 'sfp_emergingthreats',
         'sfp_blocklistde', 'sfp_botvrij', 'sfp_cinsscore', 'sfp_cybercrimetracker',
         'sfp_dronebl', 'sfp_malwarepatrol', 'sfp_phishtank', 'sfp_spamhaus',
         'sfp_talosintel', 'sfp_threatfox', 'sfp_threatminer', 'sfp_threatjammer',
         'sfp_xforce', 'sfp_pulsedive',
     ]},

    {'id': 'builtin:attack_surface', 'name': 'Attack surface', 'sort_order': 70,
     'description': 'Public-facing assets — ports, services, fingerprints, exposures',
     'modules': [
         'sfp_portscan_tcp', 'sfp_tool_nmap', 'sfp_shodan', 'sfp_censys',
         'sfp_zoomeye', 'sfp_fofa', 'sfp_binaryedge', 'sfp_tool_nuclei',
         'sfp_tool_whatweb', 'sfp_tool_wafw00f', 'sfp_tool_wappalyzer',
         'sfp_subdomain_takeover', 'sfp_sslcert', 'sfp_tool_testsslsh',
         'sfp_tool_retirejs', 'sfp_tool_snallygaster', 'sfp_builtwith',
         'sfp_fullhunt',
     ]},

    {'id': 'builtin:brand_typosquat', 'name': 'Brand & typosquat', 'sort_order': 80,
     'description': 'Look-alike domains, brand mentions, leak sites',
     'modules': [
         'sfp_tool_dnstwist', 'sfp_similar', 'sfp_company', 'sfp_crossref',
         'sfp_grayhatwarfare', 'sfp_github', 'sfp_pastebin', 'sfp_phishstats',
     ]},

    {'id': 'builtin:person_osint', 'name': 'Person OSINT', 'sort_order': 90,
     'description': 'For username, email, person, or phone targets',
     'modules': [
         'sfp_accounts', 'sfp_fullcontact', 'sfp_pgp', 'sfp_haveibeenpwned',
         'sfp_gravatar', 'sfp_emailrep', 'sfp_dehashed', 'sfp_intelx',
         'sfp_callername', 'sfp_numverify', 'sfp_keybase', 'sfp_flickr',
         'sfp_github',
     ]},

    {'id': 'builtin:quick_recon', 'name': 'Quick recon', 'sort_order': 100,
     'description': 'Fast, no API key required — finishes in minutes',
     'modules': [
         'sfp_dnsresolve', 'sfp_dnscommonsrv', 'sfp_crt', 'sfp_sslcert',
         'sfp_whois', 'sfp_company', 'sfp_robtex', 'sfp_archiveorg',
         'sfp_pageinfo', 'sfp_spider', 'sfp_email', 'sfp_countryname',
     ]},
]


def validate_module_names(names: Iterable[str], modules: dict) -> tuple:
    """Split an iterable of module names into (valid, invalid) lists.

    Deduplicates: each name appears at most once across the two outputs,
    in first-seen order. Order within each list reflects first-encounter
    order in the input iterable.
    """
    seen = set()
    valid = []
    invalid = []
    for n in names:
        if n in seen:
            continue
        seen.add(n)
        if n in modules:
            valid.append(n)
        else:
            invalid.append(n)
    return valid, invalid
