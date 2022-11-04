#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" CA handler for Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE) """
from __future__ import print_function
import os
import json

# pylint: disable=E0401, E0611, C0209
from examples.ca_handler.ms_wcce.target import Target
from examples.ca_handler.ms_wcce.request import Request

# pylint: disable=E0401
from acme_srv.helper import (
    load_config,
    convert_byte_to_string,
    convert_string_to_byte,
    proxy_check,
    build_pem_file
)


class CAhandler(object):
    """MS-WCCE CA handler"""

    def __init__(self, _debug=None, logger=None):
        self.logger = logger
        self.host = None
        self.user = None
        self.password = None
        self.template = None
        self.proxy = None
        self.target_domain = None
        self.domain_controller = None
        self.ca_name = None
        self.ca_bundle = False

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """close the connection at the end of the context"""

    def _config_host_load(self, config_dic):
        """ load host variable """
        self.logger.debug("CAhandler._config_host_load()")

        if 'host_variable' in config_dic['CAhandler']:
            try:
                self.host = os.environ[config_dic['CAhandler']['host_variable']]
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load host_variable:{0}'.format(err))
        if 'host' in config_dic['CAhandler']:
            if self.host:
                self.logger.info('CAhandler._config_load() overwrite host')
            self.host = config_dic['CAhandler']['host']

        self.logger.debug("CAhandler._config_host_load() ended")

    def _config_credentials_load(self, config_dic):
        """ load host variable """
        self.logger.debug("CAhandler._config_credentials_load()")

        if 'user_variable' in config_dic['CAhandler']:
            try:
                self.user = os.environ[config_dic['CAhandler']['user_variable']]
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load user_variable:{0}'.format(err))
        if 'user' in config_dic['CAhandler']:
            if self.user:
                self.logger.info('CAhandler._config_load() overwrite user')
            self.user = config_dic['CAhandler']['user']

        if 'password_variable' in config_dic['CAhandler']:
            try:
                self.password = os.environ[config_dic['CAhandler']['password_variable']]
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load password_variable:{0}'.format(err))
        if 'password' in config_dic['CAhandler']:
            if self.password:
                self.logger.info('CAhandler._config_load() overwrite password')
            self.password = config_dic['CAhandler']['password']

        self.logger.debug("CAhandler._config_credentials_load() ended")

    def _config_parameters_load(self, config_dic):
        """ load parameters """
        self.logger.debug("CAhandler._config_parameters_load()")

        if 'target_domain' in config_dic['CAhandler']:
            self.target_domain = config_dic['CAhandler']['target_domain']
        if 'domain_controller' in config_dic['CAhandler']:
            self.domain_controller = config_dic['CAhandler']['domain_controller']
        if 'ca_name' in config_dic['CAhandler']:
            self.ca_name = config_dic['CAhandler']['ca_name']
        if 'ca_bundle' in config_dic['CAhandler']:
            self.ca_bundle = config_dic['CAhandler']['ca_bundle']
        if 'template' in config_dic['CAhandler']:
            self.template = config_dic['CAhandler']['template']

        self.logger.debug("CAhandler._config_parameters_load()")

    def _config_proxy_load(self, config_dic):
        """ load proxy settings """
        self.logger.debug("CAhandler._config_proxy_load()")

        if 'DEFAULT' in config_dic and 'proxy_server_list' in config_dic['DEFAULT']:
            try:
                proxy_list = json.loads(config_dic['DEFAULT']['proxy_server_list'])
                proxy_server = proxy_check(self.logger, self.host, proxy_list)
                self.proxy = {'http': proxy_server, 'https': proxy_server}
            except Exception as err_:
                self.logger.warning('CAhandler._config_load() proxy_server_list failed with error: {0}'.format(err_))

        self.logger.debug("CAhandler._config_proxy_load() ended")

    def _config_load(self):
        """ " load config from file"""
        self.logger.debug("CAhandler._config_load()")
        config_dic = load_config(self.logger, "CAhandler")

        if 'CAhandler' in config_dic:

            self._config_host_load(config_dic)
            self._config_credentials_load(config_dic)
            self._config_parameters_load(config_dic)

        self._config_proxy_load(config_dic)

        self.logger.debug("CAhandler._config_load() ended")

    def _file_load(self, bundle):
        """ load file """
        file_ = None
        try:
            with open(bundle, 'r', encoding='utf-8') as fso:
                file_ = fso.read()
        except Exception as err_:
            self.logger.error('CAhandler._file_load(): could not load {0}. Error: {1}'.format(bundle, err_))
        return file_

    def request_create(self):
        """create request object """
        self.logger.debug('CAhandler.request_create()')

        target = Target(
            domain=self.target_domain,
            username=self.user,
            password=self.password,
            remote_name=self.host,
            dc_ip=self.domain_controller,
        )
        request = Request(
            target=target,
            ca=self.ca_name,
            template=self.template,
        )

        self.logger.debug('CAhandler.request_create() ended')
        return request

    def enroll(self, csr):
        """enroll certificate via MS-WCCE"""
        self.logger.debug("CAhandler.enroll({0})".format(self.template))
        cert_bundle = None
        error = None
        cert_raw = None

        if not (self.host and self.user and self.password and self.template):
            self.logger.error("Config incomplete")
            return ("Config incomplete", None, None, None)

        # create request
        request = self.request_create()

        # recode csr
        csr = build_pem_file(self.logger, None, csr, 64, True)

        # pylint: disable=W0511
        # currently getting certificate chain is not supported
        ca_pem = self._file_load(self.ca_bundle)

        try:
            # request certificate
            cert_raw = convert_byte_to_string(
                request.get_cert(convert_string_to_byte(csr))
            )
            # replace crlf with lf
            cert_raw = cert_raw.replace("\r\n", "\n")
        except Exception as err_:
            cert_raw = None
            self.logger.error("ca_server.get_cert() failed with error: {0}".format(err_))

        if cert_raw:
            if ca_pem:
                cert_bundle = cert_raw + ca_pem
            else:
                cert_bundle = cert_raw

            cert_raw = cert_raw.replace("-----BEGIN CERTIFICATE-----\n", "")
            cert_raw = cert_raw.replace("-----END CERTIFICATE-----\n", "")
            cert_raw = cert_raw.replace("\n", "")
        else:
            self.logger.error("cert bundling failed")
            error = "cert bundling failed"

        self.logger.debug("Certificate.enroll() ended")
        return (error, cert_bundle, cert_raw, None)

    def poll(self, _cert_name, poll_identifier, _csr):
        """poll status of pending CSR and download certificates"""
        self.logger.debug("CAhandler.poll()")

        error = "Method not implemented."
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug("CAhandler.poll() ended")
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, _cert, _rev_reason, _rev_date):
        """revoke certificate"""
        self.logger.debug("CAhandler.tsg_id_lookup()")
        # get serial from pem file and convert to formated hex

        code = 500
        message = "urn:ietf:params:acme:error:serverInternal"
        detail = "Revocation is not supported."

        return (code, message, detail)

    def trigger(self, _payload):
        """process trigger message and return certificate"""
        self.logger.debug("CAhandler.trigger()")

        error = "Method not implemented."
        cert_bundle = None
        cert_raw = None

        self.logger.debug("CAhandler.trigger() ended with error: {0}".format(error))
        return (error, cert_bundle, cert_raw)
