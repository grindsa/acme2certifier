#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" ca handler for  Microsoft Webenrollment service (certsrv) """
from __future__ import print_function
import os
import textwrap
import json
from OpenSSL import crypto
from OpenSSL.crypto import _lib, _ffi, X509
# pylint: disable=E0401, E0611
from examples.ca_handler.certsrv import Certsrv
# pylint: disable=E0401
from acme_srv.helper import load_config, b64_url_recode, convert_byte_to_string, proxy_check


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
        self.host = None
        self.user = None
        self.password = None
        self.auth_method = 'basic'
        self.ca_bundle = False
        self.template = None
        self.proxy = None

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _pkcs7_to_pem(self, pkcs7_content, outform='string'):
        """ convert pkcs7 to pem """
        self.logger.debug('CAhandler._pkcs7_to_pem()')
        for filetype in (crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1):
            try:
                pkcs7 = crypto.load_pkcs7_data(filetype, pkcs7_content)
                break
            except BaseException as err:
                self.logger.error('CAhandler._pkcs7_to_pem() failed with error: {0}'.format(err))
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

    def _check_credentials(self, ca_server):
        """ check creadentials """
        self.logger.debug('CAhandler.__check_credentials()')
        auth_check = ca_server.check_credentials()
        self.logger.debug('CAhandler.__check_credentials() ended with {0}'.format(auth_check))
        return auth_check

    def enroll(self, csr):
        """ enroll certificate from via MS certsrv """
        self.logger.debug('CAhandler.enroll({0})'.format(self.template))
        cert_bundle = None
        error = None
        cert_raw = None

        if self.host and self.user and self.password and self.template:
            # setup certserv
            ca_server = Certsrv(self.host, self.user, self.password, self.auth_method, self.ca_bundle, proxies=self.proxy)

            # check connection and credentials
            auth_check = self._check_credentials(ca_server)
            if auth_check:
                # recode csr
                csr = textwrap.fill(b64_url_recode(self.logger, csr), 64) + '\n'

                # get ca_chain
                try:
                    ca_pkcs7 = convert_byte_to_string(ca_server.get_chain(encoding='b64'))
                    ca_pem = self._pkcs7_to_pem(ca_pkcs7)
                    # replace crlf with lf
                    # ca_pem = ca_pem.replace('\r\n', '\n')
                except BaseException as err_:
                    ca_pem = None
                    self.logger.error('ca_server.get_chain() failed with error: {0}'.format(err_))

                try:
                    cert_raw = convert_byte_to_string(ca_server.get_cert(csr, self.template))
                    # replace crlf with lf
                    cert_raw = cert_raw.replace('\r\n', '\n')
                except BaseException as err_:
                    cert_raw = None
                    self.logger.error('ca_server.get_cert() failed with error: {0}'.format(err_))

                if ca_pem and cert_raw:
                    cert_bundle = cert_raw + ca_pem
                    cert_raw = cert_raw.replace('-----BEGIN CERTIFICATE-----\n', '')
                    cert_raw = cert_raw.replace('-----END CERTIFICATE-----\n', '')
                    cert_raw = cert_raw.replace('\n', '')
                else:
                    self.logger.error('cert bundling failed')
                    error = 'cert bundling failed'
            else:
                self.logger.error('Connection or Credentialcheck failed')
                error = 'Connection or Credentialcheck failed.'
        else:
            self.logger.error('Config incomplete')
            error = 'Config incomplete'

        self.logger.debug('Certificate.enroll() ended')
        return(error, cert_bundle, cert_raw, None)

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config(self.logger, 'CAhandler')
        if 'CAhandler' in config_dic:

            if 'host_variable' in config_dic['CAhandler']:
                try:
                    self.host = os.environ[config_dic['CAhandler']['host_variable']]
                except BaseException as err:
                    self.logger.error('CAhandler._config_load() could not load host_variable:{0}'.format(err))
            if 'host' in config_dic['CAhandler']:
                if self.host:
                    self.logger.info('CAhandler._config_load() overwrite host')
                self.host = config_dic['CAhandler']['host']
            if 'user_variable' in config_dic['CAhandler']:
                try:
                    self.user = os.environ[config_dic['CAhandler']['user_variable']]
                except BaseException as err:
                    self.logger.error('CAhandler._config_load() could not load user_variable:{0}'.format(err))
            if 'user' in config_dic['CAhandler']:
                if self.user:
                    self.logger.info('CAhandler._config_load() overwrite user')
                self.user = config_dic['CAhandler']['user']
            if 'password_variable' in config_dic['CAhandler']:
                try:
                    self.password = os.environ[config_dic['CAhandler']['password_variable']]
                except BaseException as err:
                    self.logger.error('CAhandler._config_load() could not load password_variable:{0}'.format(err))
            if 'password' in config_dic['CAhandler']:
                if self.password:
                    self.logger.info('CAhandler._config_load() overwrite password')
                self.password = config_dic['CAhandler']['password']
            if 'template' in config_dic['CAhandler']:
                self.template = config_dic['CAhandler']['template']
            if 'auth_method' in config_dic['CAhandler'] and config_dic['CAhandler']['auth_method'] == 'ntlm':
                self.auth_method = config_dic['CAhandler']['auth_method']
            # check if we get a ca bundle for verification
            if 'ca_bundle' in config_dic['CAhandler']:
                self.ca_bundle = config_dic['CAhandler']['ca_bundle']

        if 'DEFAULT' in config_dic and 'proxy_server_list' in config_dic['DEFAULT']:
            try:
                proxy_list = json.loads(config_dic['DEFAULT']['proxy_server_list'])
                proxy_server = proxy_check(self.logger, self.host, proxy_list)
                self.proxy = {'http': proxy_server, 'https': proxy_server}
            except BaseException as err_:
                self.logger.warning('Challenge._config_load() proxy_server_list failed with error: {0}'.format(err_))

        self.logger.debug('CAhandler._config_load() ended')

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
        # get serial from pem file and convert to formated hex

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        return(code, message, detail)

    def trigger(self, _payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
