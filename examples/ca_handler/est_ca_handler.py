#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca handler for generic EST server """
from __future__ import print_function
import os
import textwrap
import json
import requests
from requests.auth import HTTPBasicAuth
from OpenSSL import crypto
from OpenSSL.crypto import _lib, _ffi, X509
# pylint: disable=C0209, E0401
from acme_srv.helper import load_config, b64_decode, b64_url_recode, convert_byte_to_string, parse_url, proxy_check


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
        self.proxy = None
        self.request_timeout = 20

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
                    response = requests.get(self.est_host + '/cacerts', cert=self.est_client_cert, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout)
                else:
                    self.logger.debug('CAhandler._cacerts_get() by using userid/password')
                    response = requests.get(self.est_host + '/cacerts', auth=HTTPBasicAuth(self.est_user, self.est_password), verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout)
                pem = self._pkcs7_to_pem(b64_decode(self.logger, response.text))
            except Exception as err_:
                self.logger.error('CAhandler._cacerts_get() returned an error: {0}'.format(err_))
                error = err_
                pem = None
        else:
            self.logger.error('CAhandler._cacerts_get() configuration incomplete: "est_host" parameter is missing')
            error = None
            pem = None

        self.logger.debug('CAhandler._cacerts_get() ended with err: {0}'.format(error))
        return (error, pem)

    def _cert_bundle_create(self, error, ca_pem, cert_raw):
        """ create cert bundle """
        self.logger.debug('CAhandler._cert_bundle_create()')

        cert_bundle = None
        if not error:
            cert_bundle = cert_raw + ca_pem
            cert_raw = cert_raw.replace('-----BEGIN CERTIFICATE-----\n', '')
            cert_raw = cert_raw.replace('-----END CERTIFICATE-----\n', '')
            cert_raw = cert_raw.replace('\n', '')
        else:
            self.logger.error('CAhandler.enroll() _simpleenroll error: {0}'.format(error))

        self.logger.debug('CAhandler._cert_bundle_create()')
        return (error, cert_bundle, cert_raw)

    def _config_host_load(self, config_dic):
        """ load est server address """
        self.logger.debug('CAhandler._config_host_load()')

        if 'est_host_variable' in config_dic['CAhandler']:
            try:
                self.est_host = os.environ[config_dic['CAhandler']['est_host_variable']] + '/.well-known/est'
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load est_host_variable:{0}'.format(err))
        if 'est_host' in config_dic['CAhandler']:
            if self.est_host:
                self.logger.info('CAhandler._config_load() overwrite est_host')
            self.est_host = config_dic['CAhandler']['est_host'] + '/.well-known/est'
        if not self.est_host:
            self.logger.error('CAhandler._config_load(): missing "est_host" parameter')

        self.logger.debug('CAhandler._config_host_load() ended')

    def _config_clientauth_load(self, config_dic):
        """ check if we need to use clientauth """
        self.logger.debug('CAhandler._config_clientauth_load()')

        if 'est_client_cert' in config_dic['CAhandler'] and 'est_client_key' in config_dic['CAhandler']:
            self.est_client_cert = []
            self.est_client_cert.append(config_dic['CAhandler']['est_client_cert'])
            self.est_client_cert.append(config_dic['CAhandler']['est_client_key'])
        elif 'est_client_cert' in config_dic['CAhandler'] or 'est_client_key' in config_dic['CAhandler']:
            self.logger.error('CAhandler._config_load() configuration incomplete: either "est_client_cert or "est_client_key" parameter is missing in config file')

        self.logger.debug('CAhandler._config_clientauth_load() ended')

    def _config_userauth_load(self, config_dic):
        """ check if we need to use user-auth """
        self.logger.debug('CAhandler._config_userauth_load()')

        if 'est_user_variable' in config_dic['CAhandler']:
            try:
                self.est_user = os.environ[config_dic['CAhandler']['est_user_variable']]
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load est_user_variable:{0}'.format(err))
        if 'est_user' in config_dic['CAhandler']:
            if self.est_user:
                self.logger.info('CAhandler._config_load() overwrite est_user')
            self.est_user = config_dic['CAhandler']['est_user']

        self.logger.debug('CAhandler._config_userauth_load() ended')

    def _config_password_load(self, config_dic):
        """ load password """
        self.logger.debug('CAhandler._config_password_load()')

        if 'est_password_variable' in config_dic['CAhandler']:
            try:
                self.est_password = os.environ[config_dic['CAhandler']['est_password_variable']]
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load est_password:{0}'.format(err))
        if 'est_password' in config_dic['CAhandler']:
            if self.est_password:
                self.logger.info('CAhandler._config_load() overwrite est_password')
            self.est_password = config_dic['CAhandler']['est_password']
        if (self.est_user and not self.est_password) or (self.est_password and not self.est_user):
            self.logger.error('CAhandler._config_load() configuration incomplete: either "est_user" or "est_password" parameter is missing in config file')

        self.logger.debug('CAhandler._config_password_load() ended')

    def _config_parameters_load(self, config_dic):
        """ load config paramters """
        self.logger.debug('CAhandler._config_load()')

        # check if we get a ca bundle for verification
        if 'ca_bundle' in config_dic['CAhandler']:
            try:
                self.ca_bundle = config_dic.getboolean('CAhandler', 'ca_bundle')
            except Exception:
                self.ca_bundle = config_dic['CAhandler']['ca_bundle']

        if 'request_timeout' in config_dic['CAhandler']:
            try:
                self.request_timeout = int(config_dic['CAhandler']['request_timeout'])
            except Exception:
                self.request_timeout = 20

        self.logger.debug('CAhandler._config_load() ended')

    def _config_proxy_load(self, config_dic):
        """ load config paramters """
        self.logger.debug('CAhandler._config_proxy_load()')

        if 'DEFAULT' in config_dic and 'proxy_server_list' in config_dic['DEFAULT']:
            try:
                proxy_list = json.loads(config_dic['DEFAULT']['proxy_server_list'])
                url_dic = parse_url(self.logger, self.est_host)
                if 'host' in url_dic:
                    (fqdn, _port) = url_dic['host'].split(':')
                    proxy_server = proxy_check(self.logger, fqdn, proxy_list)
                    self.proxy = {'http': proxy_server, 'https': proxy_server}
            except Exception as err_:
                self.logger.warning('Challenge._config_load() proxy_server_list failed with error: {0}'.format(err_))

        self.logger.debug('CAhandler._config_proxy_load() ended')

    def _config_load(self):
        """" load config from file """
        # pylint: disable=R0912, R0915
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config(self.logger, 'CAhandler')

        if 'CAhandler' in config_dic:

            # load host information
            self._config_host_load(config_dic)
            # load clientauth
            self._config_clientauth_load(config_dic)
            # load user
            self._config_userauth_load(config_dic)
            # load password
            self._config_password_load(config_dic)
            # load paramters
            self._config_parameters_load(config_dic)
            # check if we have one authentication scheme
            if not self.est_client_cert and not self.est_user:
                self.logger.error('CAhandler._config_load() configuration incomplete: either user or client authentication must be configured')
            elif self.est_client_cert and self.est_user:
                self.logger.error('CAhandler._config_load() configuration wrong: user and client authentication cannot be configured together')

        # load proxy information
        self._config_proxy_load(config_dic)

        self.logger.debug('CAhandler._config_load() ended')

    def _pkcs7_to_pem(self, pkcs7_content, outform='string'):
        """ convert pkcs7 to pem """
        self.logger.debug('CAhandler._pkcs7_to_pem()')
        for filetype in (crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1):
            try:
                pkcs7 = crypto.load_pkcs7_data(filetype, pkcs7_content)
                break
            except Exception as _err:
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
                response = requests.post(self.est_host + '/simpleenroll', data=csr, cert=self.est_client_cert, headers=headers, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout)
            else:
                response = requests.post(self.est_host + '/simpleenroll', data=csr, auth=HTTPBasicAuth(self.est_user, self.est_password), headers=headers, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout)
            # response.raise_for_status()
            pem = self._pkcs7_to_pem(b64_decode(self.logger, response.text))
        except Exception as err_:
            self.logger.error('CAhandler._simpleenroll() returned an error: {0}'.format(err_))
            error = str(err_)
            pem = None

        self.logger.debug('CAhandler._simpleenroll() ended with err: {0}'.format(error))
        return (error, pem)

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
                        self.logger.error('CAhandler.enroll(): Authentication information missing.')
                    # build certificate bundle
                    (error, cert_bundle, cert_raw) = self._cert_bundle_create(error, ca_pem, cert_raw)
                else:
                    error = 'no CA certificates found'
                    self.logger.error('CAhandler.enroll(): no CA certificates found')
            else:
                self.logger.error('CAhandler.enroll() _cacerts_get error: {0}'.format(error))

        self.logger.debug('Certificate.enroll() ended')
        return (error, cert_bundle, cert_raw, None)

    def poll(self, _cert_name, poll_identifier, _csr):
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, _cert, _rev_reason, _rev_date):
        """ revoke certificate """
        self.logger.debug('CAhandler.tsg_id_lookup()')

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        self.logger.debug('CAhandler.revoke() ended')
        return (code, message, detail)

    def trigger(self, _payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
