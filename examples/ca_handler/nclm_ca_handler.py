# -*- coding: utf-8 -*-
"""ca handler for "NetGuard Certificate Lifecycle Manager" via REST-API class"""
from __future__ import print_function
import os
import time
import json
from typing import List, Tuple, Dict
import requests

# pylint: disable=e0401, r0913
from acme_srv.helper import (
    load_config,
    build_pem_file,
    b64_encode,
    b64_url_recode,
    convert_string_to_byte,
    cert_serial_get,
    uts_now,
    parse_url,
    proxy_check,
    error_dic_get,
    uts_to_date_utc,
    header_info_get,
    eab_profile_header_info_check,
    config_eab_profile_load,
    config_headerinfo_load,
    config_enroll_config_log_load,
    enrollment_config_log,
    config_allowed_domainlist_load,
    allowed_domainlist_check,
)


class CAhandler(object):
    """CA  handler"""

    def __init__(self, _debug=None, logger=None):
        self.logger = logger
        self.api_host = None
        self.nclm_version = None
        self.api_version = "/v2"
        self.ca_bundle = True
        self.credential_dic = {"api_user": None, "api_password": None}
        self.container_info_dic = {"name": None, "id": None}
        self.template_info_dic = {"name": None, "id": None}
        self.headers = None
        self.ca_name = None
        self.error = None
        self.wait_interval = 5
        self.proxy = None
        self.request_timeout = 20
        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list = []
        self.allowed_domainlist = []

    def __enter__(self):
        """Makes CAhandler a Context Manager"""
        if not self.api_host:
            self._config_load()
            self._config_check()
        if not self.headers and not self.error:
            self._login()
        if not self.container_info_dic["id"] and not self.error:
            self._container_id_lookup()
        return self

    def __exit__(self, *args):
        """cose the connection at the end of the context"""

    def _api_post(self, url: str, data: Dict[str, str]) -> Dict[str, str]:
        """generic wrapper for an API post call"""
        self.logger.debug("CAhandler._api_post()")
        try:
            response = requests.post(
                url=url,
                json=data,
                headers=self.headers,
                verify=self.ca_bundle,
                proxies=self.proxy,
                timeout=self.request_timeout,
            )
            try:
                api_response = response.json()
            except Exception:
                api_response = {"status": response.status_code}
        except Exception as err_:
            self.logger.error("CAhandler._api_post() returned error: %s", err_)
            api_response = str(err_)

        self.logger.debug("CAhandler._api_post() ended with: %s", api_response)
        return api_response

    def _ca_id_get(self, ca_list: Dict[str, str]) -> int:
        """get ca_id"""
        self.logger.debug("CAhandler._ca_id_get()")
        ca_id = None
        if "items" in ca_list:
            for ca_ in ca_list["items"]:
                # compare name or description field against config value
                if "name" in ca_ and ca_["name"] == self.ca_name:
                    # pylint: disable=R1723
                    if "id" in ca_:
                        ca_id = ca_["id"]
                        break
                    else:
                        self.logger.error(
                            "ca_id.lookup() policyLinkId field is missing  ..."
                        )

        self.logger.debug("CAhandler._ca_id_get() with %s", ca_id)
        return ca_id

    def _ca_policylink_id_lookup(self) -> int:
        """lookup CA ID based on CA_name"""
        self.logger.debug("CAhandler._ca_policylink_id_lookup()")

        # query CAs
        ca_list = requests.get(
            f'{self.api_host}{self.api_version}/containers/{self.container_info_dic["id"]}/issuers',
            headers=self.headers,
            verify=self.ca_bundle,
            proxies=self.proxy,
            timeout=self.request_timeout,
        ).json()
        if "items" in ca_list:
            ca_id = self._ca_id_get(ca_list)
        else:
            # log error
            ca_id = None
            self.logger.error("ca_id.lookup() no CAs found in response ...")

        if not ca_id:
            # log error
            self.logger.error(
                "CAhandler_ca_policylink_id_lookup(): no policylink id found for %s",
                self.ca_name,
            )
        self.logger.debug("CAhandler._ca_policylink_id_lookup() ended with: %s", ca_id)
        return ca_id

    def _cert_enroll(self, csr: str, policylink_id: int) -> Tuple[str, str, str]:
        """enroll operation"""
        self.logger.debug("CAhandler._cert_enroll()")

        error = None
        cert_bundle = None
        cert_raw = None
        cert_id = None

        # post csr
        job_id = self._csr_post(csr, policylink_id)

        if job_id:
            cert_id = self._cert_id_get(job_id)
            if cert_id:
                (error, cert_bundle, cert_raw) = self._cert_bundle_build(cert_id)
            else:
                self.logger.error(
                    "CAhandler.eroll(): certifcate_id lookup failed for job: %s", job_id
                )
                error = "Certifcate_id lookup failed"
        else:
            self.logger.error("CAhandler.eroll(): job_id lookup failed for job")
            error = "job_id lookup failed"

        self.logger.debug("CAhandler._cert_enroll() ended with error: %s", error)
        return (error, cert_bundle, cert_raw, cert_id)

    def _csr_post(self, csr: str, policylink_id: int) -> Dict[str, str]:
        """post csr"""
        self.logger.debug("CAhandler._csr_post()")

        job_id = None
        # build_pem_file
        csr = build_pem_file(self.logger, None, csr, 64, True)
        csr = b64_encode(self.logger, convert_string_to_byte(csr))
        data_dic = {"allowDuplicateCn": True, "request": {"pkcs10": csr}}

        # add template if correctly configured
        if "id" in self.template_info_dic and self.template_info_dic["id"]:
            data_dic["template"] = {"id": self.template_info_dic["id"]}

        response = self._api_post(
            f"{self.api_host}{self.api_version}/containers/{self.container_info_dic['id']}/issuers/{policylink_id}/csr",
            data_dic,
        )

        if "id" in response:
            job_id = response["id"]

        self.logger.debug("CAhandler._csr_post() ended with: %s", job_id)
        return job_id

    def _issuer_certid_get(self, cert_dic: Tuple[str, str]) -> Tuple[str, bool]:
        """get cert id of issuer"""
        self.logger.debug("CAhandler._issuer_certid_get()")

        cert_id = None
        issuer_loop = False

        if (
            isinstance(cert_dic, dict)
            and "urls" in cert_dic
            and "issuer" in cert_dic["urls"]
        ):
            self.logger.debug(
                "CAhandler._cert_bundle_build() fetch issuer : %s",
                cert_dic["urls"]["issuer"],
            )
            cert_dic = requests.get(
                self.api_host + cert_dic["urls"]["issuer"],
                headers=self.headers,
                verify=self.ca_bundle,
                proxies=self.proxy,
                timeout=self.request_timeout,
            ).json()
            if "urls" in cert_dic and "certificate" in cert_dic["urls"]:
                cert_id = cert_dic["urls"]["certificate"].replace(
                    "/v2/certificates/", ""
                )
                self.logger.debug(
                    "CAhandler._cert_bundle_build() fetch certificate for issuer-certid: %s",
                    cert_id,
                )
                issuer_loop = True

        self.logger.debug("CAhandler._issuer_certid_get() ended with: %s", cert_id)
        return (cert_id, issuer_loop)

    def _cert_bundle_build(self, cert_id: int) -> Tuple[str, str, str]:
        """download cert and create bundle"""
        self.logger.debug("CAhandler._cert_bundle_build(%s)", cert_id)
        cert_bundle = ""
        error = None
        cert_raw = None
        issuer_loop = True
        count = 0

        while issuer_loop:
            # set issuer loop to False to avoid ending in an endless loop
            issuer_loop = False
            count += 1
            self.logger.debug(
                "CAhandler._cert_bundle_build() fetch certificate for certid: %s",
                cert_id,
            )

            cert_dic = requests.get(
                f"{self.api_host}{self.api_version}/certificates/{cert_id}",
                headers=self.headers,
                verify=self.ca_bundle,
                proxies=self.proxy,
                timeout=self.request_timeout,
            ).json()
            if "der" in cert_dic:
                if count == 1:
                    # get cert_raw
                    cert_raw = cert_dic["der"]

                # build_pem_file
                cert_bundle = build_pem_file(
                    self.logger,
                    existing=cert_bundle,
                    certificate=cert_dic["der"],
                    wrap=True,
                    csr=False,
                )
                cert_id, issuer_loop = self._issuer_certid_get(cert_dic)

        # we need this for backwards compability
        if cert_bundle == "":
            cert_bundle = None

        self.logger.debug("CAhandler._cert_bundle_build() ended")
        return (error, cert_bundle, cert_raw)

    def _cert_id_get(self, job_id: int) -> int:
        """lookup get cert_id from enrollment job"""
        self.logger.debug("CAhandler._cert_id_get(%s)", job_id)

        cert_id = None
        # check job status
        cnt = 0
        while cnt < 10:
            response = requests.get(
                f"{self.api_host}{self.api_version}/jobs/{job_id}",
                headers=self.headers,
                verify=self.ca_bundle,
                proxies=self.proxy,
                timeout=self.request_timeout,
            ).json()
            if response.get("status", None) == "done":
                if (
                    len(response.get("entities", [])) > 0
                    and "ref" in response["entities"][0]
                    and response["entities"][0]["ref"].lower() == "certificate"
                    and "url" in response["entities"][0]
                ):
                    cert_id = response["entities"][0]["url"].replace(
                        "/v2/certificates/", ""
                    )
                break
            time.sleep(self.wait_interval)

        self.logger.debug("CAhandler._cert_id_get() ended with: %s", cert_id)
        return cert_id

    def _certid_get_from_serial(self, cert_raw: str) -> List[str]:
        """get certificates"""
        self.logger.debug("CAhandler._certid_get_from_serial()")

        cert_serial = cert_serial_get(self.logger, cert_raw, hexformat=True)

        # search for certificate
        try:
            cert_list = requests.get(
                f"{self.api_host}{self.api_version}/certificates?freeText=={cert_serial}&containerId={self.container_info_dic['id']}",
                headers=self.headers,
                verify=self.ca_bundle,
                proxies=self.proxy,
                timeout=self.request_timeout,
            ).json()
        except Exception as err_:
            self.logger.error(
                "CAhandler._certid_get_from_serial(): request get aborted with err: %s",
                err_,
            )
            cert_list = []

        if (
            cert_list
            and "items" in cert_list
            and len(cert_list["items"]) > 0
            and "id" in cert_list["items"][0]
        ):
            cert_id = cert_list["items"][0]["id"]
        else:
            cert_id = None
            self.logger.error(
                "CAhandler._certid_get_from_serial(): no certificate found for serial: %s",
                cert_serial,
            )

        self.logger.debug(
            "CAhandler._certid_get_from_serial() ended with code: %s", cert_id
        )
        return cert_id

    def _cert_id_lookup(self, cert_raw: str) -> int:
        """get tracking id"""
        self.logger.debug("CAhandler._cert_id_lookup()")

        cert_id = None

        # we misuse header_info_get() to get the tracking id from database
        cert_recode = b64_url_recode(self.logger, cert_raw)
        pid_list = header_info_get(
            self.logger,
            csr=cert_recode,
            vlist=["poll_identifier"],
            field_name="cert_raw",
        )

        for ele in pid_list:
            if "poll_identifier" in ele:
                cert_id = ele["poll_identifier"]
                break

        if not cert_id:
            # lookup through NCLM API
            self.logger.info(
                "CAhandler._cert_id_lookup(): cert_id not found in database. Lookup trough NCLM API"
            )
            cert_id = self._certid_get_from_serial(cert_raw)

        self.logger.debug("CAhandler._cert_id_lookup() ended with %s", cert_id)
        return cert_id

    def _config_api_access_check(self):
        """check config for consitency"""
        self.logger.debug("CAhandler._config_api_access_check()")

        if not self.api_host:
            self.logger.error('"api_host" to be set in config file')
            self.error = "api_host to be set in config file"

        if not self.error and not self.credential_dic.get("api_user"):
            self.logger.error('"api_user" to be set in config file')
            self.error = "api_user to be set in config file"

        if not self.error and not (
            "api_password" in self.credential_dic
            and self.credential_dic["api_password"]
        ):
            self.logger.error('"api_password" to be set in config file')
            self.error = "api_password to be set in config file"

        self.logger.debug("CAhandler._config_api_access_check() ended")

    def _config_names_check(self):
        """check config for consitency"""
        self.logger.debug("CAhandler._config_names_check()")

        if not self.error:
            if not (
                "name" in self.container_info_dic and self.container_info_dic["name"]
            ):
                self.logger.error('"tsg_name" to be set in config file')
                self.error = "tsg_name to be set in config file"

        if not self.error and not self.ca_name:
            self.logger.error('"ca_name" to be set in config file')
            self.error = "ca_name to be set in config file"

        if not self.error and self.ca_bundle is False:
            self.logger.warning(
                '"ca_bundle" set to "False" - validation of server certificate disabled'
            )

        self.logger.debug("CAhandler._config_names_check() ended")

    def _config_check(self):
        """check config for consitency"""
        self.logger.debug("CAhandler._config_check()")

        self._config_api_access_check()
        self._config_names_check()

        self.logger.debug("CAhandler._config_check() ended")

    def _config_api_user_load(self, config_dic: Dict[str, str]):
        """load user"""
        self.logger.debug("CAhandler._config_api_user_load()")

        if "api_user_variable" in config_dic["CAhandler"]:
            try:
                self.credential_dic["api_user"] = os.environ[
                    config_dic.get("CAhandler", "api_user_variable")
                ]
            except Exception as err:
                self.logger.error(
                    "CAhandler._config_load() could not load user_variable:%s", err
                )
        if "api_user" in config_dic["CAhandler"]:
            if self.credential_dic["api_user"]:
                self.logger.info("CAhandler._config_load() overwrite api_user")
            self.credential_dic["api_user"] = config_dic.get("CAhandler", "api_user")

        self.logger.debug("CAhandler._config_api_user_load() ended.")

    def _config_api_password_load(self, config_dic: Dict[str, str]):
        """load password"""
        self.logger.debug("CAhandler._config_api_password_load()")

        if "api_password_variable" in config_dic["CAhandler"]:
            try:
                self.credential_dic["api_password"] = os.environ[
                    config_dic.get("CAhandler", "api_password_variable")
                ]
            except Exception as err:
                self.logger.error(
                    "CAhandler._config_load() could not load password_variable:%s", err
                )
        if "api_password" in config_dic["CAhandler"]:
            if self.credential_dic["api_password"]:
                self.logger.info("CAhandler._config_load() overwrite api_password")
            self.credential_dic["api_password"] = config_dic.get(
                "CAhandler", "api_password"
            )

        self.logger.debug("CAhandler._config_api_password_load() ended")

    def _config_names_load(self, config_dic: Dict[str, str]):
        """load names from config"""
        self.logger.debug("CAhandler._config_names_load()")

        self.api_host = config_dic.get("CAhandler", "api_host", fallback=self.api_host)
        self.ca_name = config_dic.get("CAhandler", "ca_name", fallback=self.ca_name)
        self.template_info_dic["name"] = config_dic.get(
            "CAhandler", "template_name", fallback=None
        )
        if "container_name" in config_dic["CAhandler"]:
            self.container_info_dic["name"] = config_dic.get(
                "CAhandler", "container_name", fallback=None
            )
        elif "tsg_name" in config_dic["CAhandler"]:
            # for backwards compatibility
            self.logger.warning(
                "CAhandler._config_names_load() tsg_name is deprecated. Use container_name instead."
            )
            self.container_info_dic["name"] = config_dic.get(
                "CAhandler", "tsg_name", fallback=None
            )

        self.logger.debug("CAhandler._config_names_load() ended")

    def _config_proxy_load(self, config_dic: Dict[str, str]):
        """load proxy configuration"""
        self.logger.debug("CAhandler._config_proxy_load()")

        if "DEFAULT" in config_dic and "proxy_server_list" in config_dic["DEFAULT"]:
            try:
                proxy_list = json.loads(config_dic.get("DEFAULT", "proxy_server_list"))
                url_dic = parse_url(self.logger, self.api_host)
                if "host" in url_dic:
                    (fqdn, _port) = url_dic["host"].split(":")
                    proxy_server = proxy_check(self.logger, fqdn, proxy_list)
                    self.proxy = {"http": proxy_server, "https": proxy_server}
            except Exception as err_:
                self.logger.warning(
                    "Challenge._config_load() proxy_server_list failed with error: %s",
                    err_,
                )

        self.logger.debug("CAhandler._config_proxy_load() ended")

    def _config_timer_load(self, config_dic: Dict[str, str]):
        """load timer"""
        self.logger.debug("CAhandler._config_proxy_load()")

        # check if we get a ca bundle for verification
        if "ca_bundle" in config_dic["CAhandler"]:
            try:
                self.ca_bundle = config_dic.getboolean("CAhandler", "ca_bundle")
            except Exception:
                self.ca_bundle = config_dic.get(
                    "CAhandler", "ca_bundle", fallback=self.ca_bundle
                )

        if "request_timeout" in config_dic["CAhandler"]:
            try:
                self.request_timeout = int(
                    config_dic.get(
                        "CAhandler", "request_timeout", fallback=self.request_timeout
                    )
                )
            except Exception:
                self.request_timeout = 20

        self.logger.debug("CAhandler._config_proxy_load() ended")

    def _config_load(self):
        """ " load config from file"""
        # pylint: disable=r0912
        self.logger.debug("CAhandler._config_load()")
        config_dic = load_config(self.logger, "CAhandler")
        if "CAhandler" in config_dic:

            self._config_names_load(config_dic)
            self._config_api_user_load(config_dic)
            self._config_api_password_load(config_dic)
            self._config_timer_load(config_dic)

        self._config_proxy_load(config_dic)
        # load allowed domainlist
        self.allowed_domainlist = config_allowed_domainlist_load(
            self.logger, config_dic
        )
        # load profiling
        self.eab_profiling, self.eab_handler = config_eab_profile_load(
            self.logger, config_dic
        )
        # load header info
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)
        # load enrollment config log
        (
            self.enrollment_config_log,
            self.enrollment_config_log_skip_list,
        ) = config_enroll_config_log_load(self.logger, config_dic)

        self.logger.debug("CAhandler._config_load() ended")

    def _container_id_lookup(self):
        """get target system id based on name"""
        self.logger.debug(
            "CAhandler._container_id_lookup() for tsg: %s",
            self.container_info_dic["name"],
        )
        try:
            tsg_list = requests.get(
                self.api_host
                + "/containers?freeText="
                + str(self.container_info_dic["name"])
                + "&offset=0&limit=50&fetchPath=true",
                headers=self.headers,
                verify=self.ca_bundle,
                proxies=self.proxy,
                timeout=self.request_timeout,
            ).json()
        except Exception as err_:
            self.logger.error(
                "CAhandler._container_id_lookup() returned error: %s", err_
            )
            tsg_list = []

        if "items" in tsg_list:
            for tsg in tsg_list["items"]:
                if "name" in tsg and "id" in tsg:
                    if self.container_info_dic["name"] == tsg["name"]:
                        self.container_info_dic["id"] = tsg["id"]
                        break
                else:
                    self.logger.error(
                        "CAhandler._container_id_lookup() incomplete response: %s", tsg
                    )
        else:
            self.logger.error(
                "CAhandler._container_id_lookup() no target-system-groups found for filter: %s.",
                self.container_info_dic["name"],
            )
        self.logger.debug(
            "CAhandler._container_id_lookup() ended with: %s",
            str(self.container_info_dic["id"]),
        )

    def _csr_check(self, csr: str) -> str:
        """check csr"""
        self.logger.debug("CAhandler._csr_check()")

        # check for eab profiling and header_info
        error = eab_profile_header_info_check(self.logger, self, csr, "profile_id")

        if not error:
            # check for allowed domainlist
            error = allowed_domainlist_check(self.logger, csr, self.allowed_domainlist)

        self.logger.debug("CAhandler._csr_check() ended with: %s", error)
        return error

    def _enroll(self, csr: str, ca_id: int) -> Tuple[str, str, str, str]:
        """enroll certificate from NCLM"""
        self.logger.debug("CAhandler._enroll()")

        error = None
        cert_bundle = None
        cert_raw = None
        cert_id = None

        if self.enrollment_config_log:
            self.enrollment_config_log_skip_list.extend(["headers", "credential_dic"])
            enrollment_config_log(
                self.logger, self, self.enrollment_config_log_skip_list
            )

        if ca_id and self.container_info_dic["id"]:
            # enroll operation
            (error, cert_bundle, cert_raw, cert_id) = self._cert_enroll(csr, ca_id)
        else:
            error = f'Enrollment aborted. ca: {ca_id}, tsg_id: {self.container_info_dic["id"]}'
            self.logger.error(
                "CAhandler.eroll(): Enrollment aborted. ca_id: %s, container: %s",
                ca_id,
                self.container_info_dic["id"],
            )

        self.logger.debug("CAhandler._enroll() ended with: %s", error)
        return (error, cert_bundle, cert_raw, cert_id)

    def _login(self):
        """_login into NCLM API"""
        self.logger.debug("CAhandler._login()")
        # check first if API is reachable
        api_response = requests.get(
            self.api_host + "/v1", proxies=self.proxy, timeout=self.request_timeout
        )
        self.logger.debug("api response code:%s", api_response.status_code)

        if api_response.ok:
            # all fine try to login
            if "versionNumber" in api_response.json():
                self.nclm_version = api_response.json()["versionNumber"]
                self.logger.debug("NCLM version: %s", self.nclm_version)

            self.logger.debug(
                'log in to %s as user "%s"',
                self.api_host,
                self.credential_dic["api_user"],
            )
            data = {
                "username": self.credential_dic["api_user"],
                "password": self.credential_dic["api_password"],
            }
            api_response = requests.post(
                url=self.api_host
                + self.api_version
                + "/token?grant_type=client_credentials",
                json=data,
                proxies=self.proxy,
                timeout=self.request_timeout,
            )

            if api_response.ok:
                json_dic = api_response.json()
                if "access_token" in json_dic:
                    self.headers = {
                        "Authorization": f"Bearer {json_dic['access_token']}"
                    }
                    _username = json_dic.get("username", None)
                    _realms = json_dic.get("realms", None)
                    self.logger.debug(
                        "login response:\n user: %s\n token: %s\n realms: %s\n",
                        _username,
                        json_dic["access_token"],
                        _realms,
                    )
                else:
                    self.logger.error(
                        "CAhandler._login(): No token returned. Aborting."
                    )
            else:
                self.logger.error(
                    "CAhandler._login() error during post: %s", api_response.status_code
                )
        else:
            # If response code is not ok (200), print the resulting http error code with description
            self.logger.error(
                "CAhandler._login() error during get: %s", api_response.status_code
            )

    def _revocation_status_poll(
        self, job_id: int, err_dic: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """poll status of revocation job"""
        self.logger.debug("CAhandler._revocation_status_poll()")

        cnt = 0
        while cnt < 10:
            response = requests.get(
                f"{self.api_host}{self.api_version}/jobs/{job_id}",
                headers=self.headers,
                verify=self.ca_bundle,
                proxies=self.proxy,
                timeout=self.request_timeout,
            ).json()
            if "status" in response and response["status"] in ["done", "failed"]:
                if response["status"] == "done":
                    code = 200
                    message = None
                    detail = None
                elif response["status"] == "failed":
                    code = 500
                    message = err_dic["serverinternal"]
                    detail = "Revocation operation failed: error from API"
                break
            time.sleep(self.wait_interval)
            cnt += 1

        if cnt == 10:
            code = 500
            message = err_dic["serverinternal"]
            detail = "Revocation operation failed: Timeout"

        self.logger.debug("CAhandler._revocation_status_poll() ended with: %s", code)
        return (code, message, detail)

    def _template_list_get(self, ca_id: int) -> Dict[str, str]:
        """get list of templates"""
        self.logger.debug("CAhandler._template_list_get(%s)", ca_id)
        try:
            template_list = requests.get(
                f"{self.api_host}{self.api_version}/containers/{self.container_info_dic['id']}/issuers/{ca_id}/templates",
                headers=self.headers,
                verify=self.ca_bundle,
                proxies=self.proxy,
                timeout=self.request_timeout,
            ).json()
        except Exception as err_:
            self.logger.error("CAhandler._template_list_get() returned error: %s", err_)
            template_list = []

        if "items" in template_list:
            tmpl_cnt = len(template_list["items"])
        else:
            tmpl_cnt = 0

        self.logger.debug(
            "CAhandler._template_list_get() ended with: %s templates", tmpl_cnt
        )
        return template_list

    def _templates_enumerate(self, template_list: Dict[str, str]):
        """get template id based on name"""
        self.logger.debug(
            "CAhandler._templates_enumerate() for template: %s",
            self.template_info_dic["name"],
        )

        for template in template_list["items"]:
            if (
                "name" in template
                and template["name"] == self.template_info_dic["name"]
                and "id" in template
            ):
                self.template_info_dic["id"] = template["id"]
                break

    def _template_id_lookup(self, ca_id: int):
        """get template id based on name"""
        self.logger.debug(
            "CAhandler._template_id_lookup() for template: %s",
            self.template_info_dic["name"],
        )

        # get list of templates
        template_list = self._template_list_get(ca_id)

        # enumerate templates to get template-id
        if "items" in template_list:
            self._templates_enumerate(template_list)
        else:
            self.logger.error(
                "CAhandler._template_id_lookup() no templates found for filter: %s.",
                self.template_info_dic["name"],
            )

        self.logger.debug(
            "CAhandler._template_id_lookup() ended with: %s",
            str(self.template_info_dic["id"]),
        )

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """enroll certificate from NCLM"""
        self.logger.debug("CAhandler.enroll()")

        cert_bundle = None
        error = None
        cert_raw = None
        cert_id = None

        # recode csr
        csr = b64_url_recode(self.logger, csr)

        if not self.error:
            if self.container_info_dic["id"]:

                # templating
                ca_id = self._ca_policylink_id_lookup()

                if (
                    ca_id
                    and self.template_info_dic["name"]
                    and not self.template_info_dic["id"]
                ):
                    self._template_id_lookup(ca_id)

                error = self._csr_check(csr)

                if not error:
                    (error, cert_bundle, cert_raw, cert_id) = self._enroll(csr, ca_id)
                else:
                    self.logger.error(
                        "CAhandler.eroll(): EAB profile lookup failed with error: %s",
                        error,
                    )
            else:
                error = f'CAhandler.eroll(): ID lookup for container"{self.container_info_dic["name"]}" failed.'
        else:
            error = self.error
            self.logger.error(self.error)

        self.logger.debug("CAhandler.enroll() ended")
        return (error, cert_bundle, cert_raw, cert_id)

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
        self,
        cert: str,
        rev_reason: str = "unspecified",
        rev_date: str = uts_to_date_utc(uts_now()),
    ) -> Tuple[int, str, str]:
        """revoke certificate"""
        self.logger.debug("CAhandler.revoke()")

        err_dic = error_dic_get(self.logger)

        code = 500
        message = err_dic["serverinternal"]
        detail = "Revocation operation failed"

        # get tracking id as input for revocation call
        cert_id = self._cert_id_lookup(cert)

        if cert_id:
            data_dic = {"reason": rev_reason, "time": rev_date}
            response = self._api_post(
                f"{self.api_host}{self.api_version}/certificates/{cert_id}/revoke",
                data_dic,
            )
            if "urls" in response and "job" in response["urls"]:
                job_id = response["urls"]["job"].replace("/v2/jobs/", "")
            else:
                job_id = None
                self.logger.error(
                    "CAhandler.revoke(): job_id lookup failed for certificate: %s",
                    cert_id,
                )

        if job_id:
            (code, message, detail) = self._revocation_status_poll(job_id, err_dic)

        self.logger.debug("CAhandler.revoke() ended with: %s", code)
        return (code, message, detail)

    def trigger(self, _payload: str) -> Tuple[str, str, str]:
        """process trigger message and return certificate"""
        self.logger.debug("CAhandler.trigger()")

        error = "Method not implemented."
        cert_bundle = None
        cert_raw = None

        self.logger.debug("CAhandler.trigger() ended with error: %s", error)
        return (error, cert_bundle, cert_raw)
