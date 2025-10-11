#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=r0913, w0613
"""email hook class"""

'''
Copy this file from examples to f.ex /opt/acme2certifier then add this config to acme_srv.cfg

Example config:

[Hooks]
hooks_file: email_hooks.py
appname: acme2certifier
sender: acme2certifier@acme.example.com
rcpt: admin@example.com
report_failures: True
report_successes: False
'''

import smtplib

from acme_srv.helper import (
    load_config,
    cert_san_get,
    csr_san_get,
    build_pem_file,
)

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

class Hooks:
    """
    This hook requires local MTA to be configured, probably postfix.
    I will not be adding support here for anything other than localhost MTA with no auth.
    """

    def __init__(self, logger) -> None:
        self.logger = logger

        self.config_dic = load_config(self.logger, "Hooks")

        self.msg: list[str] = []
        self.san = ''

        # Mandatory keys
        required_keys = ['appname', 'sender', 'rcpt']
        missing = []
        if 'Hooks' not in self.config_dic:
            raise ValueError("Missing 'Hooks' section in configuration.")
        for key in required_keys:
            if key not in self.config_dic['Hooks']:
                missing.append(key)
        if missing:
            raise ValueError(f"Missing required configuration key(s) in [Hooks]: {', '.join(missing)}")

        self.appname = self.config_dic['Hooks']['appname']
        self.sender = self.config_dic['Hooks']['sender']
        self.rcpt = self.config_dic['Hooks']['rcpt']

        # Optionals, that default to True
        self.report_failures  = self.config_dic.getboolean('Hooks', 'report_failures', fallback=True)
        self.report_successes = self.config_dic.getboolean('Hooks', 'report_successes', fallback=True)

        self.envelope = MIMEMultipart()
        self.envelope['From'] = f'{self.appname} <{self.sender}>'
        self.envelope['To'] = self.rcpt
        self.envelope['Date'] = formatdate()
        self.done = False

    def _done(self):
        if self.done:
            raise RuntimeError('unexpected usage')

        self.done = True

        with smtplib.SMTP('localhost') as smtp:
            smtp.helo()
            self.envelope.attach(MIMEText('\n\n'.join(self.msg), 'plain'))
            smtp.sendmail(self.sender, self.rcpt, self.envelope.as_string())
            smtp.quit()

        subject = self.envelope['Subject']
        self.logger.info(f'Hook.*_hook() sent a notification to {self.rcpt} Subject: {subject}')

    def _clean_san(self, sans):
        # Grab the first one, file names can't be too long anyway
        sans = sans[0]

        # Format: DNS:a.example.com

        return sans.split(':')[1].strip()

    def _attach_csr(self, request_key, csr):
        # Attach CSR
        fn = f'{self.san}_{request_key}.csr'
        part = MIMEApplication(build_pem_file(self.logger, None, csr, 64, True), Name=fn)
        part['Content-Disposition'] = f'attachment; filename="{fn}"'
        part['Content-Type'] = 'application/x-pem-file'
        self.envelope.attach(part)

        self.msg.append(f'To read {fn} using CMD on Windows:\ncertutil -dump %USERPROFILE%\Downloads\{fn}')

    def _attach_cert(self, request_key, certificate):
        # Add crt to email
        # But cannot send as .crt because Outlook blocks that, sooo I make a pfx to wrap it inside,
        # bonus, because of pfx, i can send the CA cert too!
        cert_list = x509.load_pem_x509_certificates(certificate.encode('utf-8'))
        if len(cert_list) != 2:
            raise ValueError(f"Expected exactly 2 certificates (cert and CA), but got {len(cert_list)}")
        cert, ca = cert_list
        fn = f'{self.san}_{request_key}.pfx'
        pfx = pkcs12.serialize_key_and_certificates(
            self.san.encode('utf-8'),
            None,  # We don't even have the key, and obviously no need for it
            cert,
            [ca],
            serialization.NoEncryption()  # No keys included so no encryption needed
        )
        part = MIMEApplication(pfx, Name=fn)
        part['Content-Disposition'] = f'attachment; filename="{fn}"'
        part['Content-Type'] = 'application/x-pkcs12'
        self.envelope.attach(part)

        self.msg.append(f'To read {fn} using CMD on Windows:\ncertutil -dump %USERPROFILE%\Downloads\{fn}')

    def pre_hook(self, _certificate_name, _order_name, csr) -> None:
        pass

    def post_hook(self, request_key, _order_name, csr, error) -> None:
        """run after *attempting* to obtain/renew certificates"""
        self.logger.debug('Hook.post_hook()')

        if not self.report_failures:
            self.logger.debug('Hook.post_hook() disabled because report_failures is False')
            return

        self.san = self._clean_san(csr_san_get(self.logger, csr))

        self.envelope['Subject'] = f'{self.appname} failure: {self.san}'
        m = f'{self.appname} failure for: {self.san}\n\n----\n{error}\n----'
        self.msg.append(m)

        self._attach_csr(request_key, csr)
        self._done()

    def success_hook(
        self,
        request_key,
        _order_name,
        csr,
        certificate,
        certificate_raw,
        _poll_identifier,
    ) -> None:
        """run after each successful certificate enrollment/renewal"""
        self.logger.debug('Hook.success_hook()')

        if not self.report_successes:
            self.logger.debug('Hook.success_hook() disabled because report_successes is False')
            return

        self.san = self._clean_san(cert_san_get(self.logger, certificate_raw))

        self.envelope['Subject'] = f'{self.appname} success: {self.san}'
        m = f'{self.appname} success for: {self.san}'
        self.msg.append(m)

        self._attach_csr(request_key, csr)
        self._attach_cert(request_key, certificate)

        self._done()


# For local testing
if __name__ == '__main__':
    import logging
    from acme_srv.helper import generate_random_string

    log_mode = logging.DEBUG
    logging.basicConfig(level=log_mode)
    logger = logging.getLogger(__name__)

    # Test CSR for something.example.com
    csr = (
        'MIIBTDCB0gIBADAgMR4wHAYDVQQDExVzb21ldGhpbmcuZXhhbXBsZS5jb20wdjAQBgcqhkjOPQIBBgUr'
        'gQQAIgNiAATkHOWijzPd0n/exl3jPVrkPAAJeND6sHiOAecYxsQikE8ImBU1DT6RKBElLkUCF7ButTeq'
        'xkkfRU4Kz3pfSZe75rVqXYfN7xUzXEt2+vpqpA65q8ZGrj9ZgXKxrA89E7agMzAxBgkqhkiG9w0BCQ4x'
        'JDAiMCAGA1UdEQQZMBeCFXNvbWV0aGluZy5leGFtcGxlLmNvbTAKBggqhkjOPQQDAgNpADBmAjEAgirc'
        'tuTr4+SRJh+MsmnScYkrV+yC1qRQwUMZGgQcPy4jxmemdyQ9p6y52dzk0j2sAjEA5+OyAcRqtWeLL1Xi'
        'PoZH0NykBcCmQWMavJubfk0seZyFE0GsFjOPk7qAoJGVYZU8'
    )

    # These are just mkcert certificates for something.example.com and an autogenerated CA
    certificate = (
        '-----BEGIN CERTIFICATE-----\nMIIECjCCAnKgAwIBAgIRALGHaaUUFeRgIrUBibd8K3owDQYJKoZ'
        'IhvcNAQELBQAw\nVTEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMRUwEwYDVQQLDAxyb290'
        '\nQGJhc3Rpb24xHDAaBgNVBAMME21rY2VydCByb290QGJhc3Rpb24wHhcNMjUxMDAx\nMTQyMjMxWhcN'
        'MjgwMTAxMTQyMjMxWjBAMScwJQYDVQQKEx5ta2NlcnQgZGV2ZWxv\ncG1lbnQgY2VydGlmaWNhdGUxFT'
        'ATBgNVBAsMDHJvb3RAYmFzdGlvbjCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMVJJSx0'
        '7B5xVBF7iT1jwvP9Q7sQHBAa\nOSctCmm8FMgQAn0B1i/M5RORrxmsxe9TGYQN23mgZPrkhfFREbK3jF'
        '1qDyi5aqyv\nRUCY8c6V8gVNHqeFY/Fbo7eVpUmL6cEWCQa4/IyC8HZgWZPvK8DiNEKTS6fa++Wg\ng7'
        'hEl0Du9IENEdnJZ8S63UGUklNaUmn/lsD2SMgtDq0OJUYmU5Zn1Uryh8I4MJCu\nHY/+i4CV+6tirKYN'
        'eQYvX2lxY8AcYnRsg8x18IVO5fu7DoH18uK0YtlTMEYac+AX\nOI/6B0C6NqXse71cQs53UF/O7ew+OC'
        'kZ67CoYobAqeuiOVEEA+qTSUsCAwEAAaNq\nMGgwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsG'
        'AQUFBwMBMB8GA1UdIwQY\nMBaAFEW2GtPZX80jY6cvOq8rMMAfW1hsMCAGA1UdEQQZMBeCFXNvbWV0aG'
        'luZy5l\neGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAYEAkDCKBHuqVxcXgx7vhftzDE3M\nj8x7WC'
        '4di+rkIrxyJ3ulGHc7Pl2gyvMoKJxRCqcK4WgLH7AqDkRsQSF+/yvv+c0H\nbUYjauPfDo1yUlLIQpo3'
        '7uwJjsfQt4j/AFLpYHw2myqAsqMw1jwbXRuLyyiHWSay\nljyHhWVnbZcLZNvBwL6bV0RCuRlWCFfjlA'
        '6buXW3a23krjs8k5I4UhKaeX7d0Pvk\nx/3JxjlGlOA8tYBT8+6Aq1xOIC1MuD8h/32Cxa7vDI9VyspY'
        'bsbCBl5m2XD566/P\nRE5rn62kBBHEXiIpFrE0R1d8MFTx9PEC00jVFDWnec3Ayl2TiTpptCF/Cb5S9K'
        '6g\nEdUFUkQj9dTxX8owUbm/tYGIYrwibWzTtscb75KjSzExnZApMfNgngke8r1f6P4Y\nHRQQU7/0Bc'
        'Di2GPzCy83rN3d2DFn6U66TZG0EEEdV1e1A0gsqfgx/b6YAZsZv26H\nZ5IkqXdj3IZRDcwdYgaTrlsl'
        'kPsantdPl+x/kxP5\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIE'
        'ejCCAuKgAwIBAgIRAI5dQJ4OEZYF5sy28Iw+/zkwDQYJKoZIhvcNAQELBQAw\nVTEeMBwGA1UEChMVbW'
        'tjZXJ0IGRldmVsb3BtZW50IENBMRUwEwYDVQQLDAxyb290\nQGJhc3Rpb24xHDAaBgNVBAMME21rY2Vy'
        'dCByb290QGJhc3Rpb24wHhcNMjUxMDAx\nMTQyMjMwWhcNMzUxMDAxMTQyMjMwWjBVMR4wHAYDVQQKEx'
        'Vta2NlcnQgZGV2ZWxv\ncG1lbnQgQ0ExFTATBgNVBAsMDHJvb3RAYmFzdGlvbjEcMBoGA1UEAwwTbWtj'
        'ZXJ0\nIHJvb3RAYmFzdGlvbjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAKo5\nMM8/lupi'
        '8cOQqh5igXfGFrunERIiShzhV3EHVpQN+h3SU0BQF50DZHDTL1rHQqAn\nhPK4fgZ37s9HjssysejgYK'
        '61w9YgvoOd6dlsCTSYjpF19T9Dz5SY8yZz3lNLHcbg\nN111PZP4hyN3BtNw4ttENGuKAqHgvFO/xmzM'
        'gJtT62G4qq8VwHa8ktFa3b9Lh14/\njEOjUIkgAgHE869/deebb2ENox7nL+W0VB9o0XCqMDYF0ZF6pw'
        '4gVP2FgNbwjSgM\nci/NCW99biGHOKA5LVG4d6nNxFgOg7GdEFExzzHjjyIYQBC/ZB7ulDyQQ6KcQRn5'
        '\nbvn83SuUZ1cGRSWSndosR3LhEJaxDLbr68X7byL7PNkBM4ILAGpd+oZLCM4Z9cpF\njGW4GxilijEg'
        'Smo7gLZk++oEh3O31Wt5dyGs2BHeUDf0rHG7z+agpzK0H6Ar9Rj5\nurfDJvswioyU7jUxrpOg+4Wk/J'
        'aJWncbU49fZRtAiwYZVVHyvKf5bn+bRJK+bQID\nAQABo0UwQzAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0T'
        'AQH/BAgwBgEB/wIBADAdBgNV\nHQ4EFgQURbYa09lfzSNjpy86ryswwB9bWGwwDQYJKoZIhvcNAQELBQ'
        'ADggGBAF+y\nWudDZVtWEbNpsSz5YvZ3W0BuNwaFo5TFYhzhh4ougs/SUhvPW5dAsVBJBjTgJ4fy\nXm'
        'miptcVzrvZiaB2+muL1PT/vUhFomuyqw46smzBIrUyHHmjqdoVIhmJ4XJq/eLS\n7wMLDpTeH3kQaQWt'
        'cK1EqlPOIMn5m/st663280lB2ICyv1zSQgWIkv4YpmzAuJcm\nwYw899emEsSdf3q1lQoLR0NkBdRPSN'
        'Zcnb9+wR98Iw5Rjca/7P0A1RbbEmbayXzf\n4adhIZaaCBDhADcU6SBC5v8HsIj0tolyf7nTKarKJoKy'
        'eY1i1sXrK28vZyWykLLD\nQ7FHcRDfoAtJ2QUvxbpBXpDg/F79PDjrdjc6n8nn4RG+JIwO8j7t3GMB5c'
        'MWOnKC\nruQ4NuKcsWkcIaQIcxJTx+tOYyGqyAMzxA+VFTQ+HNjcFBnue/XJOya4dpOo1BEG\nAacSqy'
        'ipP2lMM8Xbje7snzwmutRdATxiyGKDzacEJWUMHzlkrX8WsFIUnVNMUA==\n-----END CERTIFICATE'
        '-----'
    )

    # Generate the "certificate_raw" variable from the bundle in certificate since it has all the info no need to duplicate it
    cert, ca = x509.load_pem_x509_certificates(certificate.encode('utf-8'))
    certificate_raw = ''.join(cert.public_bytes(serialization.Encoding.PEM).decode('utf-8').splitlines()[1:-1])

    # a Failure message
    request_key = generate_random_string(logger, 12)
    h = Hooks(logger)
    h.post_hook(request_key, '', csr, 'urn:ietf:params:acme:error:rejectedIdentifier')

    # a Success message
    request_key = generate_random_string(logger, 12)
    h = Hooks(logger)
    h.success_hook(request_key, '', csr, certificate, certificate_raw, '')
