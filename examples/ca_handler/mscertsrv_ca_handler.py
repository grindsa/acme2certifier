#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" ca handler for  Microsoft Webenrollment service (certsrv) """
from __future__ import print_function
import textwrap
# pylint: disable=E0401
from certsrv import Certsrv
# pylint: disable=E0401
from acme.helper import load_config, b64_url_recode

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

    def enroll(self, csr):
        """ enroll certificate from via MS certsrv """
        self.logger.debug('CAhandler.enroll()')
        cert_bundle = None
        error = None
        cert_raw = None

        if self.host and self.user and self.password and self.template:
            # setup certserv
            ca_server = Certsrv(self.host, self.user, self.password, self.auth_method, self.ca_bundle)

            # check connection and credentials
            auth_check = ca_server.check_credentials()
            if auth_check:
                # recode csr
                csr = textwrap.fill(b64_url_recode(self.logger, csr), 64) + '\n'

                # get ca_chain
                ca_pem = ca_server.get_chain(encoding='b64')
                cert_raw = ca_server.get_cert(csr, self.template)
                if cert_raw:
                    cert_bundle = cert_raw + ca_pem
                    cert_raw = cert_raw.replace('-----BEGIN CERTIFICATE-----\n', '')
                    cert_raw = cert_raw.replace('-----END CERTIFICATE-----\n', '')
                    cert_raw = cert_raw.replace('\n', '')
                else:
                    error = 'Enrollment failed'
            else:
                error = 'Connection or Credentialcheck failed.'
        else:
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


    def revoke(self, _cert, _rev_reason, _rev_date):
        """ revoke certificate """
        self.logger.debug('CAhandler.tsg_id_lookup()')
        # get serial from pem file and convert to formated hex

        code = 500
        message = 'urn:ietf:params:acme:error:serverInternal'
        detail = 'Revocation is not supported.'

        return(code, message, detail)
