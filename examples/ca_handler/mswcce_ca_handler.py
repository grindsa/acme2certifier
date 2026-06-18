# -*- coding: utf-8 -*-
"""CA handler for Microsoft Windows Client Certificate Enrollment Protocol (MS-WCCE)"""

from __future__ import print_function
import os
import json
import tempfile
import importlib
import subprocess
from typing import Tuple, Dict, Optional

# pylint: disable=e0401, e0611
from examples.ca_handler.ms_wcce.target import Target
from examples.ca_handler.ms_wcce.request import Request

# pylint: disable=E0401
from acme_srv.helper import (
    build_pem_file,
    config_eab_profile_load,
    config_enroll_config_log_load,
    config_profile_load,
    convert_byte_to_string,
    convert_string_to_byte,
    eab_profile_header_info_check,
    enrollment_config_log,
    handler_config_check,
    header_info_get,
    load_config,
    proxy_check,
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
        self.krb5_auth_backend = "impacket"
        self.krb5_principal = None
        self.krb5_keytab = None
        self.krb5_cache = None
        self.krb5_config = None
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

        cahandler_cfg = config_dic["CAhandler"]
        self.user = self._config_credential_item_load(
            config_dic,
            cahandler_cfg,
            self.user,
            "user",
            "user_variable",
            "Unable to load user variable from environment: %s",
        )
        self.password = self._config_credential_item_load(
            config_dic,
            cahandler_cfg,
            self.password,
            "password",
            "password_variable",
            "Unable to load password variable from environment: %s",
        )
        self.krb5_principal = self._config_credential_item_load(
            config_dic,
            cahandler_cfg,
            self.krb5_principal,
            "krb5_principal",
            "krb5_principal_variable",
            "Unable to load kerberos principal variable from environment: %s",
        )
        self.krb5_keytab = self._config_credential_item_load(
            config_dic,
            cahandler_cfg,
            self.krb5_keytab,
            "krb5_keytab",
            "krb5_keytab_variable",
            "Unable to load kerberos keytab variable from environment: %s",
        )
        self.krb5_cache = self._config_credential_item_load(
            config_dic,
            cahandler_cfg,
            self.krb5_cache,
            "krb5_cache",
            "krb5_cache_variable",
            "Unable to load kerberos ccache variable from environment: %s",
        )
        self.krb5_config = self._config_credential_item_load(
            config_dic,
            cahandler_cfg,
            self.krb5_config,
            "krb5_config",
            "krb5_config_variable",
            "Unable to load kerberos krb5 config variable from environment: %s",
        )

        self.logger.debug("CAhandler._config_credentials_load() ended")

    def _config_credential_item_load(
        self,
        config_dic: Dict[str, str],
        cahandler_cfg: Dict[str, str],
        current_value: Optional[str],
        cfg_key: str,
        cfg_var_key: str,
        env_load_error_msg: str,
    ) -> Optional[str]:
        """load one credential item from env variable and/or config"""
        self.logger.debug("CAhandler._config_credential_item_load(%s)", cfg_key)
        loaded_value = current_value

        if cfg_var_key in cahandler_cfg:
            try:
                loaded_value = os.environ[config_dic.get("CAhandler", cfg_var_key)]
            except Exception as err:
                self.logger.error(env_load_error_msg, err)

        if cfg_key in cahandler_cfg:
            if loaded_value:
                self.logger.info("Overwrite %s", cfg_key)
            loaded_value = config_dic.get("CAhandler", cfg_key)
        self.logger.debug(
            "CAhandler._config_credential_item_load(%s) ended with value: %s",
            cfg_key,
            "******" if loaded_value else None,
        )
        return loaded_value

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

        if "krb5_auth_backend" in config_dic["CAhandler"]:
            self.krb5_auth_backend = config_dic.get(
                "CAhandler", "krb5_auth_backend", fallback="impacket"
            ).lower()
        elif self.use_kerberos and self._kerberos_keytab_is_configured():
            self.krb5_auth_backend = "python"
            self.logger.info(
                "Auto-selected krb5_auth_backend='python' because krb5_principal and krb5_keytab are configured."
            )
        else:
            self.krb5_auth_backend = "impacket"

        if self.krb5_auth_backend not in ["impacket", "python"]:
            self.logger.warning(
                "Unknown krb5_auth_backend '%s'. Falling back to 'impacket'.",
                self.krb5_auth_backend,
            )
            self.krb5_auth_backend = "impacket"

        self.logger.debug("CAhandler._config_parameters_load()")

    def _kerberos_keytab_is_configured(self) -> bool:
        """check if keytab flow can be used"""
        result = bool(self.krb5_principal and self.krb5_keytab)
        self.logger.debug("CAhandler._kerberos_keytab_is_configured() = %s", result)
        return result

    def _kerberos_username_from_principal(self, principal: str) -> Optional[str]:
        """extract username from kerberos principal"""
        self.logger.debug("CAhandler._kerberos_username_from_principal()")
        if not principal:
            self.logger.error(
                "Kerberos principal is not configured, cannot extract username."
            )
            return None
        self.logger.debug("Extracting username from kerberos principal '%s'", principal)
        return principal.split("@", maxsplit=1)[0]

    def _kerberos_prepare_python_backend(self) -> Optional[str]:
        """prepare kerberos credentials in python using gssapi/keytab"""
        self.logger.debug("CAhandler._kerberos_prepare_python_backend()")
        if not self.use_kerberos or self.krb5_auth_backend != "python":
            return None

        if not self._kerberos_keytab_is_configured():
            return None

        if not os.path.isfile(self.krb5_keytab):
            self.logger.error(
                "Kerberos keytab file does not exist: %s", self.krb5_keytab
            )
            return "Kerberos keytab file does not exist."

        try:
            gssapi = importlib.import_module("gssapi")
        except Exception as err:
            self.logger.error("Failed to import gssapi module: %s", err)
            return "gssapi module is required for krb5_auth_backend=python."

        ccache_file = self.krb5_cache
        if not ccache_file:
            ccache_file = tempfile.NamedTemporaryFile(
                prefix="acme2certifier_krb5cc_", delete=False
            ).name
            self.logger.debug(
                "No kerberos ccache configured, created temporary ccache file: %s",
                ccache_file,
            )
            self.krb5_cache = ccache_file

        if ccache_file.startswith("FILE:"):
            ccache_file = ccache_file.split("FILE:", maxsplit=1)[1]
            self.logger.debug(
                "Normalized kerberos ccache path from FILE: prefix: %s", ccache_file
            )
            self.krb5_cache = ccache_file

        if not os.path.exists(ccache_file):
            with open(ccache_file, "a", encoding="utf-8") as ccache_handle:
                ccache_handle.write("")

        self.logger.debug("Using kerberos ccache file: %s", ccache_file)
        os.environ["KRB5CCNAME"] = ccache_file

        try:
            principal = gssapi.Name(
                self.krb5_principal,
                gssapi.NameType.kerberos_principal,
            )
        except Exception as err:
            self.logger.error(
                "Failed to build kerberos principal from '%s': %s",
                self.krb5_principal,
                err,
            )
            return (
                "Failed to build kerberos principal for kerberos keytab authentication."
            )

        # Acquire initiator creds from keytab into ccache via available backend.
        self.logger.debug(
            "Acquiring kerberos credentials for principal '%s' using keytab '%s'",
            self.krb5_principal,
            self.krb5_keytab,
        )

        if self._kerberos_acquire_with_gssapi_raw(gssapi, principal, ccache_file):
            return None

        if self._kerberos_acquire_with_gssapi_highlevel(gssapi, principal, ccache_file):
            return None

        if self._kerberos_acquire_with_kinit(ccache_file):
            return None

        return "Failed to acquire kerberos credentials via gssapi/keytab."

    def _kerberos_acquire_with_gssapi_raw(
        self,
        gssapi: object,
        principal: object,
        ccache_file: str,
    ) -> bool:
        """acquire kerberos credentials using gssapi.raw.acquire_cred_from"""
        self.logger.debug("CAhandler._kerberos_acquire_with_gssapi_raw()")
        try:
            gssapi_raw = getattr(gssapi, "raw", None)
            raw_acquire = getattr(gssapi_raw, "acquire_cred_from", None)
            if not raw_acquire:
                self.logger.debug(
                    "gssapi.raw.acquire_cred_from is not available in this gssapi build"
                )
                return False

            store = {
                b"client_keytab": self.krb5_keytab.encode("utf-8"),
                b"ccache": ccache_file.encode("utf-8"),
            }
            raw_acquire(
                store=store,
                desired_name=principal,
                cred_usage="initiate",
            )
            self.logger.debug(
                "Kerberos credentials acquired using gssapi.raw.acquire_cred_from"
            )
            return True
        except Exception as err:
            self.logger.warning(
                "Failed to acquire kerberos credentials via gssapi.raw.acquire_cred_from: %s",
                err,
            )
            return False

    def _kerberos_acquire_with_gssapi_highlevel(
        self,
        gssapi: object,
        principal: object,
        ccache_file: str,
    ) -> bool:
        """acquire kerberos credentials using gssapi.Credentials.acquire"""
        self.logger.debug("CAhandler._kerberos_acquire_with_gssapi_highlevel()")
        try:
            credentials_class = getattr(gssapi, "Credentials", None)
            credentials_acquire = getattr(credentials_class, "acquire", None)
            if not credentials_acquire:
                self.logger.debug(
                    "gssapi.Credentials.acquire is not available in this gssapi build"
                )
                return False

            credentials_acquire(
                name=principal,
                usage="initiate",
                store={
                    "client_keytab": self.krb5_keytab,
                    "ccache": ccache_file,
                },
            )
            self.logger.debug(
                "Kerberos credentials acquired using gssapi.Credentials.acquire"
            )
            return True
        except Exception as err:
            self.logger.warning(
                "Failed to acquire kerberos credentials via gssapi.Credentials.acquire: %s",
                err,
            )
            return False

    def _kerberos_acquire_with_kinit(self, ccache_file: str) -> bool:
        """acquire kerberos credentials using kinit fallback"""
        self.logger.debug("CAhandler._kerberos_acquire_with_kinit()")
        try:
            kinit_env = dict(os.environ)
            kinit_env["KRB5CCNAME"] = ccache_file
            if self.krb5_config:
                if os.path.isfile(self.krb5_config):
                    kinit_env["KRB5_CONFIG"] = self.krb5_config
                    self.logger.debug(
                        "Using kerberos config file for kinit fallback: %s",
                        self.krb5_config,
                    )
                else:
                    self.logger.warning(
                        "Configured krb5_config does not exist: %s. Ignoring for kinit fallback.",
                        self.krb5_config,
                    )
            subprocess.run(
                [
                    "kinit",
                    "-k",
                    "-t",
                    self.krb5_keytab,
                    self.krb5_principal,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=kinit_env,
            )
            self.logger.debug("Kerberos credentials acquired using kinit fallback")
            return True
        except FileNotFoundError as err:
            self.logger.error("kinit command not found: %s", err)
            return False
        except Exception as err:
            stderr = None
            if hasattr(err, "stderr") and err.stderr:
                stderr = err.stderr.decode("utf-8", errors="replace").strip()

            if stderr:
                self.logger.error(
                    "Failed to acquire kerberos credentials via kinit: %s",
                    stderr,
                )
            else:
                self.logger.error(
                    "Failed to acquire kerberos credentials via kinit: %s",
                    err,
                )
            return False

    def _config_is_complete(self) -> Tuple[bool, str]:
        """validate mandatory settings per auth mode"""
        self.logger.debug("CAhandler._config_is_complete()")
        legacy_error = (
            "Configuration incomplete: host, user, password, or template is missing."
        )

        if not (self.host and self.template):
            return (False, legacy_error)

        if not self.use_kerberos:
            if not (self.user and self.password):
                return (False, legacy_error)
            return (True, None)

        if self._kerberos_keytab_is_configured():
            if self.krb5_auth_backend == "impacket" and not self.krb5_cache:
                return (
                    False,
                    "Configuration incomplete: kerberos keytab with krb5_auth_backend=impacket requires krb5_cache.",
                )
            return (True, None)

        if self.user and self.password:
            return (True, None)

        return (
            False,
            "Configuration incomplete: kerberos is enabled but neither keytab credentials nor user/password are configured.",
        )

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

        request_user = self.user
        request_password = self.password
        request_no_pass = False
        if self.use_kerberos and self._kerberos_keytab_is_configured():
            self.logger.debug(
                "Using kerberos keytab authentication. Username will be extracted from kerberos principal and password will be empty."
            )
            request_user = self._kerberos_username_from_principal(self.krb5_principal)
            # In keytab mode credentials come from ccache, not plaintext password.
            request_password = ""
            request_no_pass = True
        target = Target(
            domain=self.target_domain,
            username=request_user,
            password=request_password,
            no_pass=request_no_pass,
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

        # Optional python-only kerberos backend: acquire creds from keytab.
        error = self._kerberos_prepare_python_backend()

        if error:
            self.logger.error("Kerberos backend setup failed: %s", error)
            return error, cert_raw, cert_bundle

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

        config_complete, config_error = self._config_is_complete()
        if not config_complete:
            self.logger.error(config_error)
            return (
                config_error,
                None,
                None,
                None,
            )

        # check for eab profiling and header_info
        error = eab_profile_header_info_check(self.logger, self, csr, "template")

        if not error:
            # enroll certificate
            error, cert_raw, cert_bundle = self._enroll(csr)

        else:
            self.logger.error("EAB profile check failed: %s", error)

        self.logger.debug("Certificate.enroll() ended")
        return (error, cert_bundle, cert_raw, None)

    def handler_check(self):
        """check if handler is ready"""
        self.logger.debug("CAhandler.check()")

        if self.use_kerberos and self._kerberos_keytab_is_configured():
            required_fields = ["host", "template", "ca_name", "target_domain"]
        else:
            required_fields = [
                "host",
                "user",
                "password",
                "template",
                "ca_name",
                "target_domain",
            ]

        error = handler_config_check(self.logger, self, required_fields)
        self.logger.debug("CAhandler.check() ended with %s", error)
        return error

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
