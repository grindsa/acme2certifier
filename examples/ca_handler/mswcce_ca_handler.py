# -*- coding: utf-8 -*-
"""CA handler for Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE)"""
from __future__ import print_function
import os
import json
from typing import Tuple, Dict

# pylint: disable=e0401, e0611
from examples.ca_handler.ms_wcce.target import Target
from examples.ca_handler.ms_wcce.request import Request

# pylint: disable=E0401
from acme_srv.helper import (
    load_config,
    convert_byte_to_string,
    convert_string_to_byte,
    proxy_check,
    build_pem_file,
    header_info_get,
    eab_profile_header_info_check,
    config_eab_profile_load,
    enrollment_config_log,
    config_enroll_config_log_load,
    config_allowed_domainlist_load,
    config_profile_load,
    allowed_domainlist_check,
    radomize_parameter_list,
)


class CAhandler(object):
    """MS-WCCE CA handler"""

    def __init__(self, _debug: bool = False, logger: object = None):
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
        self.use_kerberos = False
        self.allowed_domainlist = []
        self.header_info_field = None
        self.timeout = 5
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list = []
        self.profiles = {}

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """close the connection at the end of the context"""

    def _config_headerinfo_load(self, config_dic: Dict[str, str]):
        """load parameters"""
        self.logger.debug("_config_header_info()")

        if (
            "Order" in config_dic
            and "header_info_list" in config_dic["Order"]
            and config_dic["Order"]["header_info_list"]
        ):
            try:
                self.header_info_field = json.loads(
                    config_dic["Order"]["header_info_list"]
                )[0]
            except Exception as err_:
                self.logger.warning(
                    "Failed to parse header_info_list from configuration: %s",
                    err_,
                )

        self.logger.debug("_config_header_info() ended")

    def _config_host_load(self, config_dic: Dict[str, str]):
        """load host variable"""
        self.logger.debug("CAhandler._config_host_load()")

        if "host_variable" in config_dic["CAhandler"]:
            try:
                self.host = os.environ[config_dic.get("CAhandler", "host_variable")]
            except Exception as err:
                self.logger.error(
                    "Unable to load host variable from environment: %s", err
                )
        if "host" in config_dic["CAhandler"]:
            if self.host:
                self.logger.info("Overwrite host")
            self.host = config_dic.get("CAhandler", "host")

        self.logger.debug("CAhandler._config_host_load() ended")

    def _config_credentials_load(self, config_dic: Dict[str, str]):
        """load host variable"""
        self.logger.debug("CAhandler._config_credentials_load()")

        if "user_variable" in config_dic["CAhandler"]:
            try:
                self.user = os.environ[config_dic.get("CAhandler", "user_variable")]
            except Exception as err:
                self.logger.error(
                    "Unable to load user variable from environment: %s", err
                )
        if "user" in config_dic["CAhandler"]:
            if self.user:
                self.logger.info("Overwrite user")
            self.user = config_dic.get("CAhandler", "user")

        if "password_variable" in config_dic["CAhandler"]:
            try:
                self.password = os.environ[
                    config_dic.get("CAhandler", "password_variable")
                ]
            except Exception as err:
                self.logger.error(
                    "Unable to load password variable from environment: %s", err
                )
        if "password" in config_dic["CAhandler"]:
            if self.password:
                self.logger.info("Overwrite password")
            self.password = config_dic.get("CAhandler", "password")

        self.logger.debug("CAhandler._config_credentials_load() ended")

    def _config_parameters_load(self, config_dic: Dict[str, str]):
        """load parameters"""
        self.logger.debug("CAhandler._config_parameters_load()")

        if "domain_controller" in config_dic["CAhandler"]:
            self.domain_controller = config_dic.get("CAhandler", "domain_controller")
        elif "dns_server" in config_dic["CAhandler"]:
            self.domain_controller = config_dic.get("CAhandler", "dns_server")

        self.target_domain = config_dic.get("CAhandler", "target_domain", fallback=None)
        self.ca_name = config_dic.get("CAhandler", "ca_name", fallback=None)
        self.ca_bundle = config_dic.get("CAhandler", "ca_bundle", fallback=None)
        self.template = config_dic.get("CAhandler", "template", fallback=None)

        # load enrollment config log
        (
            self.enrollment_config_log,
            self.enrollment_config_log_skip_list,
        ) = config_enroll_config_log_load(self.logger, config_dic)
        # load allowed domainlist
        self.allowed_domainlist = config_allowed_domainlist_load(
            self.logger, config_dic
        )

        try:
            self.timeout = config_dic.getint("CAhandler", "timeout", fallback=5)
        except Exception as err_:
            self.logger.warning(
                "Failed to parse 'timeout' from configuration. Using default value 5. Error: %s",
                err_,
            )
            self.timeout = 5

        try:
            self.use_kerberos = config_dic.getboolean(
                "CAhandler", "use_kerberos", fallback=False
            )
        except Exception as err_:
            self.logger.warning(
                "Failed to parse 'use_kerberos' from configuration. Using default value False. Error: %s",
                err_,
            )

        self.logger.debug("CAhandler._config_parameters_load()")

    def _config_proxy_load(self, config_dic: Dict[str, str]):
        """load proxy settings"""
        self.logger.debug("CAhandler._config_proxy_load()")

        if "DEFAULT" in config_dic and "proxy_server_list" in config_dic["DEFAULT"]:
            try:
                proxy_list = json.loads(config_dic.get("DEFAULT", "proxy_server_list"))
                proxy_server = proxy_check(self.logger, self.host, proxy_list)
                self.proxy = {"http": proxy_server, "https": proxy_server}
            except Exception as err_:
                self.logger.warning(
                    "Failed to load proxy_server_list from configuration: %s",
                    err_,
                )

        self.logger.debug("CAhandler._config_proxy_load() ended")

    def _config_load(self):
        """ " load config from file"""
        self.logger.debug("CAhandler._config_load()")
        config_dic = load_config(self.logger, "CAhandler")

        if "CAhandler" in config_dic:

            self._config_host_load(config_dic)
            self._config_credentials_load(config_dic)
            self._config_parameters_load(config_dic)
            # load profiling
            self.eab_profiling, self.eab_handler = config_eab_profile_load(
                self.logger, config_dic
            )
            # load profiles
            self.profiles = config_profile_load(self.logger, config_dic)
            self._config_headerinfo_load(config_dic)

        self._config_proxy_load(config_dic)
        radomize_parameter_list(self.logger, self, ["host", "ca_name", "ca_bundle"])

        self.logger.debug("CAhandler._config_load() ended")

    def _file_load(self, bundle: str) -> str:
        """load file"""
        file_ = None
        try:
            with open(bundle, "r", encoding="utf-8") as fso:
                file_ = fso.read()
        except Exception as err_:
            self.logger.error("Could not load file '%s'. Error: %s", bundle, err_)
        return file_

    def request_create(self) -> Request:
        """create request object"""
        self.logger.debug("CAhandler.request_create()")

        if self.enrollment_config_log:
            enrollment_config_log(
                self.logger, self, self.enrollment_config_log_skip_list
            )

        target = Target(
            domain=self.target_domain,
            username=self.user,
            password=self.password,
            remote_name=self.host,
            dc_ip=self.domain_controller,
            timeout=self.timeout,
        )
        request = Request(
            target=target,
            ca=self.ca_name,
            template=self.template,
            do_kerberos=self.use_kerberos,
        )

        self.logger.debug("CAhandler.request_create() ended")
        return request

    def _template_name_get(self, csr: str) -> str:
        """get templaate from csr"""
        self.logger.debug("CAhandler._template_name_get(%s)", csr)
        template_name = None

        # parse profileid from http_header
        header_info = header_info_get(self.logger, csr=csr)
        if header_info:
            try:
                header_info_dic = json.loads(header_info[-1]["header_info"])
                if self.header_info_field in header_info_dic:
                    for ele in header_info_dic[self.header_info_field].split(" "):
                        if "template" in ele.lower():
                            template_name = ele.split("=")[1]
                            break
            except Exception as err:
                self.logger.error("Failed to parse template from header info: %s", err)

        self.logger.debug(
            "CAhandler._template_name_get() ended with: %s", template_name
        )
        return template_name

    def _enroll(self, csr: str) -> Tuple[str, str, str]:
        """enroll certificate via MS-WCCE"""
        self.logger.debug("CAhandler._enroll(%s)", self.template)
        error = None
        cert_raw = None
        cert_bundle = None

        # create request
        request = self.request_create()

        # reformat csr
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
        except Exception as err:
            cert_raw = None
            self.logger.error("Enrollment failed with error: %s", err)
            error = "Could not get certificate from CA server"

        if not error and cert_raw:
            if ca_pem:
                cert_bundle = cert_raw + ca_pem
            else:
                cert_bundle = cert_raw
            cert_raw = cert_raw.replace("-----BEGIN CERTIFICATE-----\n", "")
            cert_raw = cert_raw.replace("-----END CERTIFICATE-----\n", "")
            cert_raw = cert_raw.replace("\n", "")
        else:
            self.logger.error(
                "Certificate bundling failed: CA certificate or issued certificate is missing."
            )
            error = "Certificate bundling failed: CA certificate or issued certificate is missing."

        self.logger.debug("CAhandler._enroll() ended with error: %s", error)
        return error, cert_raw, cert_bundle

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """enroll certificate via MS-WCCE"""
        self.logger.debug("CAhandler.enroll(%s)", self.template)
        cert_bundle = None
        error = None
        cert_raw = None

        if not (self.host and self.user and self.password and self.template):
            self.logger.error(
                "Configuration incomplete: host, user, password, or template is missing."
            )
            return (
                "Configuration incomplete: host, user, password, or template is missing.",
                None,
                None,
                None,
            )

        # check for allowed domainlist
        error = allowed_domainlist_check(self.logger, csr, self.allowed_domainlist)

        if not error:

            # check for eab profiling and header_info
            error = eab_profile_header_info_check(self.logger, self, csr, "template")

            if not error:
                # enroll certificate
                (error, cert_raw, cert_bundle) = self._enroll(csr)

            else:
                self.logger.error("EAB profile check failed: %s", error)
        else:
            self.logger.error("Domain not allowed for enrollment: %s", error)

        self.logger.debug("Certificate.enroll() ended")
        return (error, cert_bundle, cert_raw, None)

    def poll(
        self, _cert_name: str, poll_identifier: str, _csr: str
    ) -> Tuple[str, str, str, str, bool]:
        """poll status of pending CSR and download certificates"""
        self.logger.debug("CAhandler.poll()")

        error = "Method not implemented."
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug("CAhandler.poll() ended")
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(
        self, _cert: str, _rev_reason: str, _rev_date: str
    ) -> Tuple[int, str, str]:
        """revoke certificate"""
        self.logger.debug("CAhandler.tsg_id_lookup()")
        # get serial from pem file and convert to formated hex

        code = 500
        message = "urn:ietf:params:acme:error:serverInternal"
        detail = "Revocation is not supported."

        return (code, message, detail)

    def trigger(self, _payload: str) -> Tuple[str, str, str]:
        """process trigger message and return certificate"""
        self.logger.debug("CAhandler.trigger()")

        error = "Method not implemented."
        cert_bundle = None
        cert_raw = None

        self.logger.debug("CAhandler.trigger() ended with error: %s", error)
        return (error, cert_bundle, cert_raw)
