# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         spiderfoot.net.ssl
# Purpose:      SSL/TLS socket and certificate functionality extracted from sflib.SpiderFoot.
#
# Original author: Steve Micallef <steve@binarypool.com>
# -------------------------------------------------------------------------------

import logging
import re
import socket
import ssl
import time
from datetime import datetime

import cryptography
import OpenSSL


class SpiderFootSsl:
    """SSL/TLS utilities extracted from SpiderFoot.

    Attributes:
        log (logging.Logger): logger instance
    """

    def __init__(self, logger: logging.Logger) -> None:
        self.log = logger

    def safeSocket(self, host: str, port: int, timeout: int) -> 'ssl.SSLSocket':
        """Create a safe socket that's using SOCKS/TOR if it was enabled.

        Args:
            host (str): host
            port (int): port
            timeout (int): timeout

        Returns:
            sock
        """
        sock = socket.create_connection((host, int(port)), int(timeout))
        sock.settimeout(int(timeout))
        return sock

    def safeSSLSocket(self, host: str, port: int, timeout: int) -> 'ssl.SSLSocket':
        """Create a safe SSL connection that's using SOCKs/TOR if it was enabled.

        Args:
            host (str): host
            port (int): port
            timeout (int): timeout

        Returns:
            sock
        """
        s = socket.socket()
        s.settimeout(int(timeout))
        s.connect((host, int(port)))
        sock = ssl.wrap_socket(s)
        sock.do_handshake()
        return sock

    def parseCert(self, rawcert: str, fqdn: str = None, expiringdays: int = 30) -> dict:
        """Parse a PEM-format SSL certificate.

        Args:
            rawcert (str): PEM-format SSL certificate
            fqdn (str): expected FQDN for certificate
            expiringdays (int): The certificate will be considered as "expiring" if within this number of days of expiry.

        Returns:
            dict: certificate details
        """
        if not rawcert:
            self.log.error(f"Invalid certificate: {rawcert}")
            return None

        ret = dict()
        if '\r' in rawcert:
            rawcert = rawcert.replace('\r', '')
        if isinstance(rawcert, str):
            rawcert = rawcert.encode('utf-8')

        from cryptography.hazmat.backends.openssl import backend
        cert = cryptography.x509.load_pem_x509_certificate(rawcert, backend)
        sslcert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, rawcert)
        sslcert_dump = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, sslcert)

        ret['text'] = sslcert_dump.decode('utf-8', errors='replace')
        ret['issuer'] = str(cert.issuer)
        ret['altnames'] = list()
        ret['expired'] = False
        ret['expiring'] = False
        ret['mismatch'] = False
        ret['certerror'] = False
        ret['issued'] = str(cert.subject)

        # Expiry info
        try:
            notafter = datetime.strptime(sslcert.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%SZ")
            ret['expiry'] = int(notafter.strftime("%s"))
            ret['expirystr'] = notafter.strftime("%Y-%m-%d %H:%M:%S")
            now = int(time.time())
            warnexp = now + (expiringdays * 86400)
            if ret['expiry'] <= warnexp:
                ret['expiring'] = True
            if ret['expiry'] <= now:
                ret['expired'] = True
        except BaseException as e:
            self.log.error(f"Error processing date in certificate: {e}")
            ret['certerror'] = True
            return ret

        # SANs
        try:
            ext = cert.extensions.get_extension_for_class(cryptography.x509.SubjectAlternativeName)
            for x in ext.value:
                if isinstance(x, cryptography.x509.DNSName):
                    ret['altnames'].append(x.value.lower().encode('raw_unicode_escape').decode("ascii", errors='replace'))
        except BaseException as e:
            self.log.debug(f"Problem processing certificate: {e}")

        certhosts = list()
        try:
            attrs = cert.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)

            if len(attrs) == 1:
                name = attrs[0].value.lower()
                # CN often duplicates one of the SANs, don't add it then
                if name not in ret['altnames']:
                    certhosts.append(name)
        except BaseException as e:
            self.log.debug(f"Problem processing certificate: {e}")

        # Check for mismatch
        if fqdn and ret['issued']:
            fqdn = fqdn.lower()

            try:
                # Extract the CN from the issued section (use boundary match to avoid
                # evil.example.com matching a check for example.com)
                issued_lower = ret['issued'].lower()
                if re.search(r'\bcn=' + re.escape(fqdn) + r'(?:\b|,|$)', issued_lower):
                    certhosts.append(fqdn)

                # Extract subject alternative names
                for host in ret['altnames']:
                    certhosts.append(host.replace("dns:", ""))

                ret['hosts'] = certhosts

                self.log.debug(f"Checking for {fqdn} in certificate subject")
                fqdn_tld = ".".join(fqdn.split(".")[1:]).lower()

                found = False
                for chost in certhosts:
                    if chost == fqdn:
                        found = True
                    if chost == "*." + fqdn_tld:
                        found = True
                    if chost == fqdn_tld:
                        found = True

                if not found:
                    ret['mismatch'] = True
            except BaseException as e:
                self.log.error(f"Error processing certificate: {e}")
                ret['certerror'] = True

        return ret
