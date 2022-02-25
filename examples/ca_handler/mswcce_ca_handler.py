#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" CA handler for Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE) """
from __future__ import print_function
import os
import textwrap
import json
from OpenSSL.crypto import _lib, _ffi, X509

# pylint: disable=E0401, E0611
from examples.ca_handler.ms_wcce.target import Target
from examples.ca_handler.ms_wcce.request import Request

# pylint: disable=E0401
from acme_srv.helper import (
    load_config,
    b64_url_recode,
    convert_byte_to_string,
    convert_string_to_byte,
    proxy_check,
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

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """close the connection at the end of the context"""

    def enroll(self, csr):
        """enroll certificate via MS-WCCE"""
        self.logger.debug("CAhandler.enroll({0})".format(self.template))
        cert_bundle = None
        error = None
        cert_raw = None

        if not (self.host and self.user and self.password and self.template):
            self.logger.error("Config incomplete")
            return ("Config incomplete", None, None, None)

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

        # recode csr
        csr = textwrap.fill(b64_url_recode(self.logger, csr), 64) + "\n"

        # TODO: currently getting certificate chain is not supported
        ca_pem = ""

        try:
            # request certificate
            cert_raw = convert_byte_to_string(
                request.get_cert(convert_string_to_byte(csr))
            )
            # replace crlf with lf
            cert_raw = cert_raw.replace("\r\n", "\n")
        except Exception as err_:
            cert_raw = None
            self.logger.error(
                "ca_server.get_cert() failed with error: {0}".format(err_)
            )

        if cert_raw:
            cert_bundle = cert_raw + ca_pem
            cert_raw = cert_raw.replace("-----BEGIN CERTIFICATE-----\n", "")
            cert_raw = cert_raw.replace("-----END CERTIFICATE-----\n", "")
            cert_raw = cert_raw.replace("\n", "")
        else:
            self.logger.error("cert bundling failed")
            error = "cert bundling failed"

        self.logger.debug("Certificate.enroll() ended")
        return (error, cert_bundle, cert_raw, None)

    def _config_load(self):
        """ " load config from file"""
        self.logger.debug("CAhandler._config_load()")
        config_dic = load_config(self.logger, "CAhandler")
        if config_ca_handler := config_dic.get("CAhandler"):

            def _get_config_from_env_or_config_file(name, optional=False):
                result = None
                if variable := config_ca_handler.get(f"{name}_variable"):
                    try:
                        result = os.environ[variable]
                    except Exception as err:
                        self.logger.error(
                            "CAhandler._config_load() could not load host_variable:{0}".format(
                                err
                            )
                        )
                if config_host := config_ca_handler.get(name):
                    if result:
                        self.logger.info(f"CAhandler._config_load() overwrite {name}")
                    result = config_host
                if not optional and not result:
                    self.logger.error(
                        f'CAhandler._config_load() configuration incomplete: "{name}" parameter is missing in config file'
                    )
                return result

            self.host = _get_config_from_env_or_config_file("host")
            self.user = _get_config_from_env_or_config_file("user")
            self.password = _get_config_from_env_or_config_file("password")
            self.target_domain = _get_config_from_env_or_config_file("target_domain")
            self.domain_controller = _get_config_from_env_or_config_file(
                "domain_controller"
            )
            self.ca_name = _get_config_from_env_or_config_file("ca_name")
            self.template = config_ca_handler.get("template", self.template)

        if config_default := config_dic.get("DEFAULT"):
            if config_proxy_server_list := config_default("proxy_server_list"):
                try:
                    proxy_list = json.loads(config_proxy_server_list)
                    proxy_server = proxy_check(self.logger, self.host, proxy_list)
                    self.proxy = {"http": proxy_server, "https": proxy_server}
                except Exception as err_:
                    self.logger.warning(
                        "Challenge._config_load() proxy_server_list failed with error: {0}".format(
                            err_
                        )
                    )

        self.logger.debug("CAhandler._config_load() ended")

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
