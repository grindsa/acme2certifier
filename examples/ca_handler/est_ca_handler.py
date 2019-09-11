#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca handler for generic EST server """
from __future__ import print_function
import textwrap
import requests
from OpenSSL import crypto
from acme.helper import load_config, b64_decode, b64_url_recode

def get_certificates(self):
    """
    https://github.com/pyca/pyopenssl/pull/367/files#r67300900

    Returns all certificates for the PKCS7 structure, if present. Only
    objects of type ``signedData`` or ``signedAndEnvelopedData`` can embed
    certificates.

    :return: The certificates in the PKCS7, or :const:`None` if
        there are none.
    :rtype: :class:`tuple` of :class:`X509` or :const:`None`
    """
    from OpenSSL.crypto import _lib, _ffi, X509
    certs = _ffi.NULL
    if self.type_is_signed():
        certs = self._pkcs7.d.sign.cert
    elif self.type_is_signedAndEnveloped():
        certs = self._pkcs7.d.signed_and_enveloped.cert

    pycerts = []
    for i in range(_lib.sk_X509_num(certs)):
        pycert = X509.__new__(X509)
        pycert._x509 = _lib.sk_X509_value(certs, i)
        pycerts.append(pycert)

    if not pycerts:
        return None
    return tuple(pycerts)


class CAhandler(object):
    """ EST CA  handler """

    def __init__(self, _debug=None, logger=None):
        self.logger = logger
        self.est_host = None
        self.est_client_cert = False
        self.ca_bundle = False

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.est_host:
            self.load_config()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def cacerts_get(self):
        """ get ca certs from cerver """
        self.logger.debug('CAhandler.cacerts_get()')
        error = None
        try:
            response = requests.get(self.est_host + '/cacerts', cert=self.est_client_cert, verify=self.ca_bundle)
            response.raise_for_status()
            pem = self.pkcs7_to_pem(b64_decode(self.logger, response.text))
        except BaseException as error:
            pem = None

        self.logger.debug('CAhandler.cacerts_get() ended with err: {0}'.format(error))
        return(error, pem)

    def enroll(self, csr):
        """ enroll certificate from NCLM """
        self.logger.debug('CAhandler.enroll()')
        cert_bundle = None
        error = None
        cert_raw = None

        # recode csr
        csr = textwrap.fill(b64_url_recode(self.logger, csr), 64) + '\n'

        if self.est_host:
            (error, ca_pem) = self.cacerts_get()
            if not error:
                (error, cert_raw) = self.simpleenroll(csr)
                if not error:
                    cert_bundle = cert_raw + ca_pem
                    cert_raw = cert_raw.replace('-----BEGIN CERTIFICATE-----\n', '')
                    cert_raw = cert_raw.replace('-----END CERTIFICATE-----\n', '')
                    cert_raw = cert_raw.replace('\n', '')
        self.logger.debug('Certificate.enroll() ended')
        return(error, cert_bundle, cert_raw)

    def load_config(self):
        """" load config from file """
        self.logger.debug('CAhandler.load_config()')
        config_dic = load_config(self.logger, 'CAhandler')
        if 'est_host' in config_dic['CAhandler']:
            self.est_host = config_dic['CAhandler']['est_host'] + '/.well-known/est'

        # check if we need to use clientauth
        if 'est_client_cert' in config_dic['CAhandler'] and 'est_client_key' in config_dic['CAhandler']:
            self.est_client_cert = []
            self.est_client_cert.append(config_dic['CAhandler']['est_client_cert'])
            self.est_client_cert.append(config_dic['CAhandler']['est_client_key'])

        # check if we get a ca bundle for verification
        if 'ca_bundle' in config_dic['CAhandler']:
            self.ca_bundle = config_dic['CAhandler']['ca_bundle']
        self.logger.debug('CAhandler.load_config() ended')

    def pkcs7_to_pem(self, pkcs7_content, outform='string'):
        """ convert pkcs7 to pem """
        self.logger.debug('CAhandler.pkcs7_to_pem()')
        for filetype in (crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1):
            try:
                pkcs7 = crypto.load_pkcs7_data(filetype, pkcs7_content)
                break
            except crypto.Error as _err:
                pkcs7 = None
                # print(err)

        cert_pem_list = []
        if pkcs7:
            # convert cert pkcs#7 to pem
            cert_list = get_certificates(pkcs7)
            for cert in cert_list:
                cert_pem_list.append(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        # define output format
        if outform == 'string':
            return ''.join(cert_pem_list)
        elif outform == 'list':
            return cert_pem_list
        else:
            return None

    def simpleenroll(self, csr):
        """EST /simpleenroll request."""
        # print(csr)
        error = None
        try:
            headers = {'Content-Type': 'application/pkcs10'}
            response = requests.post(self.est_host + '/simpleenroll', data=csr, cert=self.est_client_cert, headers=headers, verify=self.ca_bundle)
            response.raise_for_status()
            pem = self.pkcs7_to_pem(b64_decode(self.logger, response.text))
        except BaseException as error:
            pem = None
        return(error, pem)

    def revoke(self, _cert, _rev_reason, _rev_date):
        """ revoke certificate """
        self.logger.debug('CAhandler.tsg_id_lookup()')
        # get serial from pem file and convert to formated hex

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        return(code, message, detail)
