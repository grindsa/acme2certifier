#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" ca handler for  Microsoft Webenrollment service (certsrv) """
from __future__ import print_function
import textwrap
from OpenSSL import crypto
from OpenSSL.crypto import _lib, _ffi, X509
# pylint: disable=E0401
from certsrv import Certsrv
# pylint: disable=E0401
from acme.helper import load_config, b64_url_recode, convert_byte_to_string

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

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.host:
            self.load_config()
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
            except crypto.Error as _err:
                pkcs7 = None
                # print(err)

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
            ca_server = Certsrv(self.host, self.user, self.password, self.auth_method, self.ca_bundle)

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

    def load_config(self):
        """" load config from file """
        self.logger.debug('CAhandler.load_config()')
        config_dic = load_config(self.logger, 'CAhandler')
        if 'host' in config_dic['CAhandler']:
            self.host = config_dic['CAhandler']['host']
        if 'user' in config_dic['CAhandler']:
            self.user = config_dic['CAhandler']['user']
        if 'password' in config_dic['CAhandler']:
            self.password = config_dic['CAhandler']['password']
        if 'template' in config_dic['CAhandler']:
            self.template = config_dic['CAhandler']['template']
        if 'auth_method' in config_dic['CAhandler']:
            self.auth_method = config_dic['CAhandler']['auth_method']
        # check if we get a ca bundle for verification
        if 'ca_bundle' in config_dic['CAhandler']:
            self.ca_bundle = config_dic['CAhandler']['ca_bundle']
        self.logger.debug('CAhandler.load_config() ended')

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

        error = None
        cert_bundle = 'Method not implemented.'
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
