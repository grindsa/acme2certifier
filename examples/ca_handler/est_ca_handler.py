#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca handler for generic EST server """
from __future__ import print_function
import textwrap
import requests
from requests.auth import HTTPBasicAuth
from OpenSSL import crypto
from OpenSSL.crypto import _lib, _ffi, X509
# pylint: disable=E0401
from acme.helper import load_config, b64_decode, b64_url_recode, convert_byte_to_string

def _get_certificates(self):
    """
    https://github.com/pyca/pyopenssl/pull/367/files#r67300900

    Returns all certificates for the PKCS7 structure, if present. Only
    objects of type ``signedData`` or ``signedAndEnvelopedData`` can embed
    certificates.

    :return: The certificates in the PKCS7, or :const:`None` if
        there are none.
    :rtype: :class:`tuple` of :class:`X509` or :const:`None`
    """
    certs = _ffi.NULL
    if self.type_is_signed():
        # pylint: disable=W0212
        certs = self._pkcs7.d.sign.cert
    elif self.type_is_signedAndEnveloped():
        # pylint: disable=W0212
        certs = self._pkcs7.d.signed_and_enveloped.cert

    pycerts = []
    for i in range(_lib.sk_X509_num(certs)):
        pycert = X509.__new__(X509)
        # pylint: disable=W0212
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
        self.est_user = None
        self.est_password = None
        self.ca_bundle = True
    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.est_host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _cacerts_get(self):
        """ get ca certs from cerver """
        self.logger.debug('CAhandler._cacerts_get()')
        error = None
        if self.est_host:
            try:
                if self.est_client_cert:
                    self.logger.debug('CAhandler._cacerts_get() by using client-certs')
                    # client auth
                    response = requests.get(self.est_host + '/cacerts', cert=self.est_client_cert, verify=self.ca_bundle)
                else:
                    self.logger.debug('CAhandler._cacerts_get() by using userid/password')
                    response = requests.get(self.est_host + '/cacerts', auth=HTTPBasicAuth(self.est_user, self.est_password), verify=self.ca_bundle)
                pem = self._pkcs7_to_pem(b64_decode(self.logger, response.text))
            except BaseException as err_:
                self.logger.error('CAhandler._cacerts_get() returned an error: {0}'.format(err_))
                error = err_
                pem = None
        else:
            self.logger.error('CAhandler._cacerts_get() configuration incomplete: "est_host" parameter is missing')
            error = None
            pem = None

        self.logger.debug('CAhandler._cacerts_get() ended with err: {0}'.format(error))
        return(error, pem)

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config(self.logger, 'CAhandler')

        if 'est_host' in config_dic['CAhandler']:
            self.est_host = config_dic['CAhandler']['est_host'] + '/.well-known/est'
        else:
            self.logger.error('CAhandler._config_load(): missing "est_host" parameter in config file')

        # check if we need to use clientauth
        if 'est_client_cert' in config_dic['CAhandler'] and 'est_client_key' in config_dic['CAhandler']:
            self.est_client_cert = []
            self.est_client_cert.append(config_dic['CAhandler']['est_client_cert'])
            self.est_client_cert.append(config_dic['CAhandler']['est_client_key'])
        elif 'est_client_cert' in config_dic['CAhandler'] or 'est_client_key' in config_dic['CAhandler']:
            self.logger.error('CAhandler._config_load() configuration incomplete: either "est_client_cert or "est_client_key" parameter is missing in config file')

        # check if we need to use user-auth
        if 'est_user' in config_dic['CAhandler'] and 'est_password' in config_dic['CAhandler']:
            self.est_user = config_dic['CAhandler']['est_user']
            self.est_password = config_dic['CAhandler']['est_password']
        elif 'est_user' in config_dic['CAhandler'] or 'est_password' in config_dic['CAhandler']:
            self.logger.error('CAhandler._config_load() configuration incomplete: either "est_user" or "est_password" parameter is missing in config file')

        # check if we have one authentication scheme
        if not self.est_client_cert and not self.est_user:
            self.logger.error('CAhandler._config_load() configuration incomplete: either user or client authentication must be configured')
        elif self.est_client_cert and self.est_user:
            self.logger.error('CAhandler._config_load() configuration wrong: user and client authentication cannot be configured together')

        # check if we get a ca bundle for verification
        if 'ca_bundle' in config_dic['CAhandler']:
            try:
                self.ca_bundle = config_dic.getboolean('CAhandler', 'ca_bundle')
            except BaseException:
                self.ca_bundle = config_dic['CAhandler']['ca_bundle']

        self.logger.debug('CAhandler._config_load() ended')

    def _pkcs7_to_pem(self, pkcs7_content, outform='string'):
        """ convert pkcs7 to pem """
        self.logger.debug('CAhandler._pkcs7_to_pem()')
        for filetype in (crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1):
            try:
                pkcs7 = crypto.load_pkcs7_data(filetype, pkcs7_content)
                break
            except BaseException as _err:
                pkcs7 = None

        cert_pem_list = []
        if pkcs7:
            # convert cert pkcs#7 to pem
            cert_list = _get_certificates(pkcs7)
            for cert in cert_list:
                cert_pem_list.append(convert_byte_to_string(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)))

        # define output format
        if outform == 'string':
            result = ''.join(cert_pem_list)
        elif outform == 'list':
            result = cert_pem_list
        else:
            result = None

        self.logger.debug('Certificate._pkcs7_to_pem() ended')
        return result

    def _simpleenroll(self, csr):
        """EST /simpleenroll request."""
        self.logger.debug('CAhandler._simpleenroll()')
        error = None
        try:
            headers = {'Content-Type': 'application/pkcs10'}
            if self.est_client_cert:
                # client auth
                response = requests.post(self.est_host + '/simpleenroll', data=csr, cert=self.est_client_cert, headers=headers, verify=self.ca_bundle)
            else:
                response = requests.post(self.est_host + '/simpleenroll', data=csr, auth=HTTPBasicAuth(self.est_user, self.est_password), headers=headers, verify=self.ca_bundle)
            # response.raise_for_status()
            pem = self._pkcs7_to_pem(b64_decode(self.logger, response.text))
        except BaseException as err_:
            self.logger.error('CAhandler._simpleenroll() returned an error: {0}'.format(err_))
            error = str(err_)
            pem = None

        self.logger.debug('CAhandler._simpleenroll() ended with err: {0}'.format(error))
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
            (error, ca_pem) = self._cacerts_get()
            if not error:
                if ca_pem:
                    if self.est_user or self.est_client_cert:
                        (error, cert_raw) = self._simpleenroll(csr)
                    else:
                        error = 'Authentication information missing'
                        self.logger.error('CAhandler.enroll(): {0}'.format(error))
                    if not error:
                        cert_bundle = cert_raw + ca_pem
                        cert_raw = cert_raw.replace('-----BEGIN CERTIFICATE-----\n', '')
                        cert_raw = cert_raw.replace('-----END CERTIFICATE-----\n', '')
                        cert_raw = cert_raw.replace('\n', '')
                    else:
                        self.logger.error('CAhandler.enroll(): {0}'.format(error))
                else:
                    error = 'no CA certificates found'
                    self.logger.error('CAhandler.enroll(): {0}'.format(error))
            else:
                self.logger.error('CAhandler.enroll(): {0}'.format(error))

        self.logger.debug('Certificate.enroll() ended')
        return(error, cert_bundle, cert_raw, None)

    def poll(self, _cert_name, poll_identifier, _csr):
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug('CAhandler.poll() ended')
        return(error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, _cert, _rev_reason, _rev_date):
        """ revoke certificate """
        self.logger.debug('CAhandler.tsg_id_lookup()')

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        self.logger.debug('CAhandler.revoke() ended')
        return(code, message, detail)

    def trigger(self, _payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
