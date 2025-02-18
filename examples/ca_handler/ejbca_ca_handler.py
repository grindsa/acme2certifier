# -*- coding: utf-8 -*-
""" ejbca rest ca handler """
import os
from typing import Tuple, Dict
import requests
from requests_pkcs12 import Pkcs12Adapter
# pylint: disable=e0401
from acme_srv.helper import load_config, build_pem_file, b64_url_recode, cert_der2pem, b64_decode, convert_byte_to_string, cert_serial_get, cert_issuer_get, encode_url, config_eab_profile_load, config_headerinfo_load, eab_profile_header_info_check, config_enroll_config_log_load, enrollment_config_log, config_allowed_domainlist_load, allowed_domainlist_check_error


class CAhandler(object):
    """ ejbca rest handler class """

    def __init__(self, _debug: bool = False, logger: object = None):
        self.logger = logger
        self.api_host = None
        self.ca_bundle = True
        self.proxy = None
        self.request_timeout = 5
        self.cert_profile_name = None
        self.ee_profile_name = None
        self.ca_name = None
        self.session = None
        self.username = None
        self.enrollment_code = None
        self.cert_passphrase = None
        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False
        self.enrollment_config_log = False
        self.enrollment_config_log_skip_list = []
        self.allowed_domainlist = []

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.api_host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _cert_status_check(self, issuer_dn: str, cert_serial: str) -> Dict[str, str]:
        """ check certificate status """
        self.logger.debug('CAhandler._cert_status_check(%s: %s)', issuer_dn, cert_serial)

        # define path
        path = f"/ejbca/ejbca-rest-api/v1/certificate/{encode_url(self.logger, issuer_dn)}/{cert_serial}/revocationstatus"

        if self.api_host:
            try:
                certstatus_response = self.session.get(self.api_host + path, proxies=self.proxy, verify=self.ca_bundle, timeout=self.request_timeout).json()
            except Exception as err_:
                self.logger.error('CAhandler._ca_get() returned error: %s', str(err_))
                certstatus_response = {'status': 'nok', 'error': str(err_)}
        else:
            self.logger.error('CAhandler._status_get(): api_host option is misisng in configuration')
            certstatus_response = {}

        return certstatus_response

    def _config_server_load(self, config_dic: Dict[str, str]):
        """ load server information """
        self.logger.debug('CAhandler._config_auth_load()')

        if 'CAhandler' in config_dic:

            self.api_host = config_dic['CAhandler'].get('api_host', None)
            self.request_timeout = config_dic['CAhandler'].get('request_timeout', 5)
            self.ca_bundle = config_dic['CAhandler'].get('ca_bundle', True)

        self.logger.debug('CAhandler._config_server_load() ended')

    def _config_authuser_load(self, config_dic: Dict[str, str]):
        self.logger.debug('CAhandler._config_authuser_load()')
        if 'username_variable' in config_dic['CAhandler'] or 'username' in config_dic['CAhandler']:
            if 'username_variable' in config_dic['CAhandler']:
                try:
                    self.username = os.environ[config_dic['CAhandler']['username_variable']]
                except Exception as err:
                    self.logger.error('CAhandler._config_authuser_load() could not load username_variable:%s', err)

            if 'username' in config_dic['CAhandler']:
                if self.username:
                    self.logger.info('CAhandler._config_load() overwrite username')
                self.username = config_dic['CAhandler']['username']
        else:
            self.logger.error('CAhandler._config_authuser_load() configuration incomplete: "username" parameter is missing in config file')

        self.logger.debug('CAhandler._config_auth_load() ended')

    def _config_enrollmentcode_load(self, config_dic: Dict[str, str]):
        self.logger.debug('CAhandler._config_enrollmentcode_load()')
        if 'enrollment_code_variable' in config_dic['CAhandler'] or 'enrollment_code' in config_dic['CAhandler']:
            if 'enrollment_code_variable' in config_dic['CAhandler']:
                try:
                    self.enrollment_code = os.environ[config_dic['CAhandler']['enrollment_code_variable']]
                except Exception as err:
                    self.logger.error('CAhandler._config_authuser_load() could not load enrollment_code_variable:%s', err)

            if 'enrollment_code' in config_dic['CAhandler']:
                if self.enrollment_code:
                    self.logger.info('CAhandler._config_load() overwrite enrollment_code')
                self.enrollment_code = config_dic['CAhandler']['enrollment_code']
        else:
            self.logger.error('CAhandler._config_authuser_load() configuration incomplete: "enrollment_code" parameter is missing in config file')

        self.logger.debug('CAhandler._config_enrollmentcode_load() ended')

    def _config_session_load(self, config_dic: Dict[str, str]):
        self.logger.debug('CAhandler._config_session_load()')

        if 'cert_passphrase_variable' in config_dic['CAhandler'] or 'cert_passphrase' in config_dic['CAhandler']:
            if 'cert_passphrase_variable' in config_dic['CAhandler']:
                try:
                    self.cert_passphrase = os.environ[config_dic['CAhandler']['cert_passphrase_variable']]
                except Exception as err:
                    self.logger.error('CAhandler._config_authuser_load() could not load cert_passphrase_variable:%s', err)

            if 'cert_passphrase' in config_dic['CAhandler']:
                if self.cert_passphrase:
                    self.logger.info('CAhandler._config_load() overwrite cert_passphrase')
                self.cert_passphrase = config_dic['CAhandler']['cert_passphrase']

        if config_dic and 'cert_file' in config_dic['CAhandler'] and self.cert_passphrase:
            with requests.Session() as self.session:
                self.session.mount(self.api_host, Pkcs12Adapter(pkcs12_filename=config_dic['CAhandler']['cert_file'], pkcs12_password=config_dic['CAhandler']['cert_passphrase']))
        else:
            self.logger.error('CAhandler._config_load(): configuration incomplete: "cert_file"/"cert_passphrase" parameter is missing in configuration file.')

        self.logger.debug('CAhandler._config_session_load() ended')

    def _config_auth_load(self, config_dic: Dict[str, str]):
        """ load authentication information """
        self.logger.debug('CAhandler._config_authuser_load()')

        if 'CAhandler' in config_dic:
            # load user
            self._config_authuser_load(config_dic)
            self._config_enrollmentcode_load(config_dic)
            self._config_session_load(config_dic)

        self.logger.debug('CAhandler._config_auth_load() ended')

    def _config_cainfo_load(self, config_dic: Dict[str, str]):
        """ load ca information """
        self.logger.debug('CAhandler._config_cainfo_load()')

        if 'CAhandler' in config_dic:
            self.ca_name = config_dic['CAhandler'].get('ca_name', None)
            self.cert_profile_name = config_dic['CAhandler'].get('cert_profile_name', None)
            self.ee_profile_name = config_dic['CAhandler'].get('ee_profile_name', None)

        self.logger.debug('CAhandler._config_cainfo_load() ended')

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')

        config_dic = load_config(self.logger, 'CAhandler')

        # load configuration
        self._config_server_load(config_dic)
        self._config_auth_load(config_dic)
        self._config_cainfo_load(config_dic)

        # load allowed domainlist
        self.allowed_domainlist = config_allowed_domainlist_load(self.logger, config_dic)
        # load profiling
        self.eab_profiling, self.eab_handler = config_eab_profile_load(self.logger, config_dic)
        # load header info
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)

        # check configuration for completeness
        variable_dic = self.__dict__
        for ele in ['api_host', 'cert_profile_name', 'ee_profile_name', 'ca_name', 'username', 'enrollment_code']:
            if not variable_dic[ele]:
                self.logger.error('CAhandler._config_load(): configuration incomplete: parameter "%s" is missing in configuration file.', ele)

        # load enrollment config log
        self.enrollment_config_log, self.enrollment_config_log_skip_list = config_enroll_config_log_load(self.logger, config_dic)
        self.logger.debug('CAhandler._config_load() ended')

    def _api_post(self, url: str, data: Dict[str, str]) -> Dict[str, str]:
        """ generic wrapper for an API post call """
        self.logger.debug('_api_post(%s)', url)

        try:
            api_response = self.session.post(url, json=data, proxies=self.proxy, verify=self.ca_bundle, timeout=self.request_timeout).json()
        except Exception as err_:
            self.logger.error('CAhandler._api_post() returned error: %s', err_)
            api_response = str(err_)

        return api_response

    def _api_put(self, url: str) -> Dict[str, str]:
        """ generic wrapper for an API put call """
        self.logger.debug('_api_put(%s)', url)

        try:
            api_response = self.session.put(url, proxies=self.proxy, verify=self.ca_bundle, timeout=self.request_timeout).json()
        except Exception as err_:
            self.logger.error('CAhandler._api_put() returned error: %s', err_)
            api_response = str(err_)

        return api_response

    def _enroll(self, csr: str) -> Tuple[str, str, str]:
        """ enroll certificate """
        self.logger.debug('CAhandler._enroll()')
        cert_bundle = None
        error = None
        cert_raw = None

        # prepare the CSR to be signed
        csr = build_pem_file(self.logger, None, b64_url_recode(self.logger, csr), None, True)

        if self.enrollment_config_log:
            enrollment_config_log(self.logger, self, self.enrollment_config_log_skip_list)

        sign_response = self._sign(csr)

        if 'certificate' in sign_response and 'certificate_chain' in sign_response:
            cert_raw = sign_response['certificate']
            cert_bundle = convert_byte_to_string(cert_der2pem(b64_decode(self.logger, cert_raw)))
            for ca_cert in sign_response['certificate_chain']:
                cert_bundle = f'{cert_bundle}{convert_byte_to_string(cert_der2pem(b64_decode(self.logger, ca_cert)))}'
        else:
            error = 'Malformed response'
            self.logger.error('CAhandler.enroll(): Malformed Rest response: %s', sign_response)

        self.logger.debug('CAhandler._enroll() ended with error: %s', error)
        return (error, cert_bundle, cert_raw)

    def _status_get(self) -> Dict[str, str]:
        """ get status of the rest-api """
        self.logger.debug('_status_get()')

        if self.api_host:
            try:
                api_response = self.session.get(self.api_host + '/ejbca/ejbca-rest-api/v1/certificate/status', proxies=self.proxy, verify=self.ca_bundle, timeout=self.request_timeout).json()
            except Exception as err_:
                self.logger.error('CAhandler._ca_get() returned error: %s', str(err_))
                api_response = {'status': 'nok', 'error': str(err_)}
        else:
            self.logger.error('CAhandler._status_get(): api_host parameter is missing in configuration')
            api_response = {}

        self.logger.debug('CAhandler._status_get() ended')
        return api_response

    def _sign(self, csr: str) -> Dict[str, str]:
        """ submit CSR for signing """
        self.logger.debug('CAhandler._sign()')
        data_dic = {
            "certificate_request": csr,
            "certificate_profile_name": self.cert_profile_name,
            "end_entity_profile_name": self.ee_profile_name,
            "certificate_authority_name": self.ca_name,
            "username": self.username,
            "password": self.enrollment_code,
            "include_chain": True,
        }

        if self.api_host:
            sign_response = self._api_post(self.api_host + "/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll", data_dic)
        else:
            self.logger.error('CAhandler._status_get(): api_host is misisng in configuration')
            sign_response = {}

        return sign_response

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """ process csr  """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None

        status_dic = self._status_get()

        if 'status' in status_dic and status_dic['status'].lower() == 'ok':

            # check for eab profiling and header_info
            error = eab_profile_header_info_check(self.logger, self, csr, 'cert_profile_name')

            if not error:
                # check for allowed domainlist
                error = allowed_domainlist_check_error(self.logger, csr, self.allowed_domainlist)

            if not error:
                # cnroll certificate
                (error, cert_bundle, cert_raw) = self._enroll(csr)
            else:
                self.logger.error('CAhandler.enroll: CSR rejected. %s', error)
        else:
            # error in status respoinse from ejbca rest api
            if 'error' in status_dic:
                error = status_dic['error']
            else:
                error = 'Unknown error'
                self.logger.error('CAhandler.enroll(): Unknown error')

        self.logger.debug('Certificate.enroll() ended')
        return (error, cert_bundle, cert_raw, poll_indentifier)

    def poll(self, _cert_name: str, poll_identifier: str, _csr: str) -> Tuple[str, str, str, str, bool]:
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, cert: str, rev_reason: str = 'UNSPECIFIED', rev_date: str = None) -> Tuple[int, str, str]:
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke(%s: %s)', rev_reason, rev_date)
        code = None
        message = None
        detail = None

        # get cert serial number and issuerdn
        cert_serial = cert_serial_get(self.logger, cert, hexformat=True)
        issuer_dn = cert_issuer_get(self.logger, cert)

        # check status
        certstatus_dic = self._cert_status_check(issuer_dn, cert_serial)

        if 'revoked' in certstatus_dic:
            if not certstatus_dic['revoked']:
                # this is the revocation path
                path = f"/ejbca/ejbca-rest-api/v1/certificate/{encode_url(self.logger, issuer_dn)}/{cert_serial}/revoke?reason={rev_reason.upper()}"
                revoke_response = self._api_put(self.api_host + path)

                if 'revoked' in revoke_response and revoke_response['revoked']:
                    code = 200
                else:
                    code = 400
                    message = 'urn:ietf:params:acme:error:serverInternal'
                    detail = str(revoke_response)
            else:
                # already revoked
                code = 400
                message = 'urn:ietf:params:acme:error:alreadyRevoked'
                detail = 'Certificate has already been revoked'
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:serverInternal'
            detail = 'Unknown status'

        self.logger.debug('Certificate.revoke() ended')
        return (code, message, detail)

    def trigger(self, _payload: str) -> Tuple[str, str, str]:
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: %s', error)
        return (error, cert_bundle, cert_raw)
