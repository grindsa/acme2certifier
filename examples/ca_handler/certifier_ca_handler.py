# -*- coding: utf-8 -*-
""" ca handler for Insta Certifier via REST-API class """
from __future__ import print_function
import textwrap
import math
import time
import json
import os
from typing import List, Tuple, Dict
import requests
from requests.auth import HTTPBasicAuth
# pylint: disable=e0401
from acme_srv.helper import load_config, cert_serial_get, uts_now, uts_to_date_utc, b64_decode, b64_encode, cert_pem2der, parse_url, proxy_check, error_dic_get, header_info_get


class CAhandler(object):
    """ CA  handler """

    def __init__(self, debug: bool = False, logger: object = None):
        self.debug = debug
        self.logger = logger
        self.request_timeout = 20
        self.api_host = None
        self.api_user = None
        self.api_password = None
        self.ca_bundle = True
        self.ca_name = None
        self.auth = None
        self.polling_timeout = 60
        self.profile_id = None
        self.proxy = None
        self.header_info_field = False

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        if not self.api_host:
            self._config_load()
            self._auth_set()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _auth_set(self):
        """ set basic authentication header """
        self.logger.debug('CAhandler._auth_set()')
        if self.api_user and self.api_password:
            self.auth = HTTPBasicAuth(self.api_user, self.api_password)
        else:
            self.logger.error('CAhandler._auth_set(): auth information incomplete. Either "api_user" or "api_password" parameter is missing in config file')
        self.logger.debug('CAhandler._auth_set() ended')

    def _api_poll(self, request_dic: Dict[str, str]) -> Tuple[str, str, str]:
        """ poll request """
        self.logger.debug('CAhandler._api_poll()')

        cert_bundle = None
        cert_raw = None

        if 'certificate' in request_dic:
            # poll identifier for later storage
            cert_dic = requests.get(request_dic['certificate'], auth=self.auth, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
            if 'certificateBase64' in cert_dic:
                # this is a valid cert generate the bundle
                error = None
                cert_bundle = self._pem_cert_chain_generate(cert_dic)
                cert_raw = cert_dic['certificateBase64']
            else:
                error = 'certificateBase64 is missing in cert request response'
        else:
            error = 'No certificate structure in request response'

        self.logger.debug('CAhandler._api_poll() ended')
        return (error, cert_bundle, cert_raw)

    def _api_post(self, url: str, data: Dict[str, str]) -> Dict[str, str]:
        """
        generic wrapper for an API post call
        args:
            url - API URL
            data - data to post
        returns:
            result of the post command
        """
        try:
            api_response = requests.post(url=url, json=data, auth=self.auth, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        except Exception as err_:
            self.logger.error('CAhandler._api_post() returned error: %s', err_)
            api_response = str(err_)

        return api_response

    def _ca_get(self, filter_key: str = None, filter_value: str = None) -> Dict[str, str]:
        """ get list of CAs"""
        self.logger.debug('_ca_get(%s:%s)', filter_key, filter_value)
        params = {}

        if filter_key:
            params['q'] = f'{filter_key}:{filter_value}'

        if self.api_host:
            try:
                api_response = requests.get(self.api_host + '/v1/cas', auth=self.auth, params=params, proxies=self.proxy, verify=self.ca_bundle, timeout=self.request_timeout).json()
            except Exception as err_:
                self.logger.error('CAhandler._ca_get() returned error: %s', str(err_))
                api_response = {'status': 500, 'message': str(err_), 'statusMessage': 'Internal Server Error'}
        else:
            self.logger.error('CAhandler._ca_get(): api_host is misisng in configuration')
            api_response = {}
        self.logger.debug('CAhandler._ca_get() ended with: %s', api_response)
        return api_response

    def _ca_get_properties(self, filter_key: str, filter_value: str) -> Dict[str, str]:
        """ get properties for a single CAs"""
        self.logger.debug('_ca_get_properties(%s:%s)', filter_key, filter_value)
        ca_list = self._ca_get(filter_key, filter_value)
        ca_dic = {}
        if 'status' in ca_list and 'message' in ca_list:
            # we got an error from get_ca()
            ca_dic = ca_list
        elif 'cas' in ca_list and ca_list['cas']:
            for cas in ca_list['cas']:
                if filter_key in cas and cas[filter_key] == filter_value:
                    ca_dic = cas
                    break
        if not ca_dic:
            ca_dic = {'status': 404, 'message': 'CA not found', 'statusMessage': 'Not Found'}
        self.logger.debug('CAhandler._ca_get_properties() ended with: %s', ca_dic)
        return ca_dic

    def _cert_get(self, csr: str) -> Dict[str, str]:
        """ get certificate from CA """
        self.logger.debug('CAhandler._cert_get(%s)', csr)
        ca_dic = self._ca_get_properties('name', self.ca_name)
        cert_dic = {}

        if self.header_info_field:
            # parse profileid from http_header
            self.profile_id = self._profile_id_get(csr=csr)

        if 'href' in ca_dic:
            data = {'ca': ca_dic['href'], 'pkcs10': csr}

            # set profileid if configured
            if self.profile_id:
                data['profileId'] = self.profile_id

            cert_dic = self._api_post(self.api_host + '/v1/requests', data)

        if not cert_dic:
            cert_dic = ca_dic

        self.logger.debug('CAhandler._cert_get() ended with: %s', cert_dic)
        return cert_dic

    def _cert_get_properties(self, serial: str, ca_link: str) -> Dict[str, str]:
        """ get properties for a single cert """
        self.logger.debug('_cert_get_properties(%s:%s)', serial, ca_link)

        params = {'q': f'issuer-id:{ca_link},serial-number:{serial}'}
        try:
            api_response = requests.get(self.api_host + '/v1/certificates', auth=self.auth, params=params, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        except Exception as err_:
            self.logger.error('CAhandler._cert_get_properties() returned error: %s', str(err_))
            api_response = {'status': 500, 'message': str(err_), 'statusMessage': 'Internal Server Error'}
        self.logger.debug('CAhandler._cert_get_properties() ended')
        return api_response

    def _certificate_revoke(self, serial: str, ca_dic: Dict[str, str], rev_reason: str, rev_date: str) -> Tuple[int, str, str]:
        self.logger.debug('CAhandler._certificate_revoke()')

        code = None
        message = None
        detail = None

        # get error message
        err_dic = error_dic_get(self.logger)

        # get certificate information via rest by search for ca+ serial
        cert_dic = self._cert_get_properties(serial, ca_dic['href'])
        if 'certificates' in cert_dic:
            if len(cert_dic['certificates']) > 0 and 'href' in cert_dic['certificates'][0]:
                # revoke the cert
                data = {'newStatus': 'revoked', 'crlReason': rev_reason, 'invalidityDate': rev_date}
                cert_dic = self._api_post(cert_dic['certificates'][0]['href'] + '/status', data)
                if 'status' in cert_dic:
                    code = 400
                    message = err_dic['alreadyrevoked']
                    if 'message' in cert_dic:
                        detail = cert_dic['message']
                    else:
                        detail = 'no details'
                else:
                    code = 200
                    message = None
                    detail = None
            else:
                code = 404
                message = err_dic['serverinternal']
                detail = 'Cert path could not be found'
        else:
            code = 404
            message = err_dic['serverinternal']
            detail = 'Cert could not be found'

        return (code, message, detail)

    def _config_user_load(self, config_dic: Dict[str, str]):
        """ load username """
        self.logger.debug('_config_user_load()')
        if 'api_user' in config_dic['CAhandler'] or 'api_user_variable' in config_dic['CAhandler']:
            if 'api_user_variable' in config_dic['CAhandler']:
                try:
                    self.api_user = os.environ[config_dic['CAhandler']['api_user_variable']]
                except Exception as err:
                    self.logger.error('CAhandler._config_load() could not load user_variable:%s', err)
            if 'api_user' in config_dic['CAhandler']:
                if self.api_user:
                    self.logger.info('CAhandler._config_load() overwrite api_user')
                self.api_user = config_dic['CAhandler']['api_user']
        else:
            self.logger.error('CAhandler._config_load() configuration incomplete: "api_user" parameter is missing in config file')

        self.logger.debug('_config_user_load() ended')

    def _config_password_load(self, config_dic: Dict[str, str]):
        """ load password """
        self.logger.debug('_config_password_load()')

        if 'api_password' in config_dic['CAhandler'] or 'api_password_variable' in config_dic['CAhandler']:
            if 'api_password_variable' in config_dic['CAhandler']:
                try:
                    self.api_password = os.environ[config_dic['CAhandler']['api_password_variable']]
                except Exception as err:
                    self.logger.error('CAhandler._config_load() could not load passphrase_variable:%s', err)
            if 'api_password' in config_dic['CAhandler']:
                if self.api_password:
                    self.logger.info('CAhandler._config_load() overwrite api_password_variable')
                self.api_password = config_dic['CAhandler']['api_password']
        else:
            self.logger.error('CAhandler._config_load() configuration incomplete: "api_password" parameter is missing in config file')

        self.logger.debug('_config_password_load() ended')

    def _config_parameter_load(self, config_dic: Dict[str, str]):
        """ load parameters """
        self.logger.debug('_config_parameter_load()')

        if 'ca_name' in config_dic['CAhandler']:
            self.ca_name = config_dic['CAhandler']['ca_name']
        else:
            self.logger.error('CAhandler._config_load() configuration incomplete: "ca_name" parameter is missing in config file')

        if 'polling_timeout' in config_dic['CAhandler']:
            self.polling_timeout = int(config_dic['CAhandler']['polling_timeout'])

        if 'request_timeout' in config_dic['CAhandler']:
            try:
                self.request_timeout = int(config_dic['CAhandler']['request_timeout'])
            except Exception:
                self.request_timeout = 20

        # load profile_id
        self.profile_id = config_dic['CAhandler'].get('profile_id', None)

        # check if we get a ca bundle for verification
        if 'ca_bundle' in config_dic['CAhandler']:
            try:
                self.ca_bundle = config_dic.getboolean('CAhandler', 'ca_bundle')
            except Exception:
                self.ca_bundle = config_dic['CAhandler']['ca_bundle']

        self.logger.debug('_config_parameter_load() ended')

    def _config_proxy_load(self, config_dic: Dict[str, str]):
        """ load parameters """
        self.logger.debug('_config_proxy_load()')

        if 'DEFAULT' in config_dic and 'proxy_server_list' in config_dic['DEFAULT']:
            try:
                proxy_list = json.loads(config_dic['DEFAULT']['proxy_server_list'])
                url_dic = parse_url(self.logger, self.api_host)
                if 'host' in url_dic:
                    (fqdn, _port) = url_dic['host'].split(':')
                    proxy_server = proxy_check(self.logger, fqdn, proxy_list)
                    self.proxy = {'http': proxy_server, 'https': proxy_server}
            except Exception as err_:
                self.logger.warning('Challenge._config_load() proxy_server_list failed with error: %s', err_)

        self.logger.debug('_config_proxy_load() ended')

    def _config_headerinfo_get(self, config_dic: Dict[str, str]):
        """ load parameters """
        self.logger.debug('_config_header_info()')

        if 'Order' in config_dic and 'header_info_list' in config_dic['Order'] and config_dic['Order']['header_info_list']:
            try:
                self.header_info_field = json.loads(config_dic['Order']['header_info_list'])[0]
            except Exception as err_:
                self.logger.warning('Order._config_orderconfig_load() header_info_list failed with error: %s', err_)

        self.logger.debug('_config_header_info() ended')

    def _config_load(self):
        """" load config from file """
        # pylint: disable=R0912, R0915
        self.logger.debug('_config_load()')
        config_dic = load_config(self.logger, 'CAhandler')
        if 'CAhandler' in config_dic:
            if 'api_host' in config_dic['CAhandler']:
                self.api_host = config_dic['CAhandler']['api_host']
            else:
                self.logger.error('CAhandler._config_load() configuration incomplete: "api_host" parameter is missing in config file')

            # load user from config
            self._config_user_load(config_dic)
            # load password from config
            self._config_password_load(config_dic)
            # load parameters from config
            self._config_parameter_load(config_dic)
            # load headerinfo
            self._config_headerinfo_get(config_dic)

        # load proxy configuration
        self._config_proxy_load(config_dic)

        self.logger.debug('CAhandler._config_load() ended')

    def _poll_cert_get(self, request_dic: Dict[str, str], poll_identifier: str, error: str) -> Tuple[str, str, str, str, bool]:
        """ get certificate via poll request """
        self.logger.debug('CAhandler._poll_cert_get()')

        cert_bundle = None
        cert_raw = None
        break_loop = False
        # check response
        if 'status' in request_dic:
            if request_dic['status'] == 'accepted':

                if 'certificate' in request_dic:
                    # poll identifier for later storage
                    cert_dic = requests.get(request_dic['certificate'], auth=self.auth, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
                    # pylint: disable=R1723
                    if 'certificateBase64' in cert_dic:
                        # this is a valid cert generate the bundle
                        error = None
                        cert_bundle = self._pem_cert_chain_generate(cert_dic)
                        cert_raw = cert_dic['certificateBase64']
                        poll_identifier = None
                        break_loop = True
                    else:
                        error = 'Request accepted but no certificateBase64 returned'
                else:
                    error = 'Request accepted but no certificate returned'
            elif request_dic['status'] == 'rejected':
                error = 'Request rejected by operator'
                poll_identifier = None
                break_loop = True

        self.logger.debug('CAhandler._poll_cert_get() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, break_loop)

    def _loop_poll(self, request_url: str) -> Tuple[str, str, str, str]:
        """ poll request """
        self.logger.debug('CAhandler._loop_poll(%s)', request_url)

        error = None
        cert_bundle = None
        cert_raw = None

        if request_url:
            # calculate iterations based on timeout
            poll_cnt = math.ceil(self.polling_timeout / 5)
            cnt = 1
            while cnt <= poll_cnt:
                cnt += 1
                request_dic = requests.get(request_url, auth=self.auth, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()

                # check response
                (error, cert_bundle, cert_raw, poll_identifier, break_loop) = self._poll_cert_get(request_dic, request_url, error)
                if break_loop:
                    break

                # sleep
                time.sleep(self.request_timeout)
        else:
            self.logger.error('CAhandler._loop_poll(): no request url specified')
            poll_identifier = request_url

        self.logger.debug('CAhandler._loop_poll() ended with error: %s', error)
        return (error, cert_bundle, cert_raw, poll_identifier)

    def _pem_list_cert_get(self, cert_dic: Dict[str, str]) -> Dict[str, str]:
        self.logger.debug('CAhandler._pem_list_cert_get()')
        if 'issuer' in cert_dic:
            self.logger.debug('issuer found: %s', cert_dic['issuer'])
            ca_cert_dic = requests.get(cert_dic['issuer'], auth=self.auth, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        else:
            self.logger.debug('issuer found: %s', cert_dic['issuerCa'])
            ca_cert_dic = requests.get(cert_dic['issuerCa'], auth=self.auth, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()

        cert_dic = {}
        if 'certificates' in ca_cert_dic:
            if 'active' in ca_cert_dic['certificates']:
                cert_dic = requests.get(ca_cert_dic['certificates']['active'], auth=self.auth, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()

        self.logger.debug('CAhandler._pem_list_cert_get() ended')
        return cert_dic

    def _pem_list_build(self, cert_dic: Dict[str, str]) -> List[str]:
        self.logger.debug('CAhandler._pem_list_build()')

        pem_list = []
        issuer_loop = True
        while issuer_loop:
            if 'certificateBase64' in cert_dic:
                pem_list.append(cert_dic['certificateBase64'])
            else:
                # stop if there is no pem content in the json response
                issuer_loop = False  # lgtm [py/unused-local-variable]
                break
            if 'issuer' in cert_dic or 'issuerCa' in cert_dic:
                cert_dic = self._pem_list_cert_get(cert_dic)
            else:
                issuer_loop = False   # lgtm [py/unused-local-variable]
                break

        self.logger.debug('CAhandler._pem_list_build() ended')
        return pem_list

    def _pem_cert_chain_generate(self, cert_dic: str) -> str:
        """ build certificate chain based """
        self.logger.debug('CAhandler._pem_cert_chain_generate()')

        if cert_dic:
            pem_list = self._pem_list_build(cert_dic)
        else:
            pem_list = []

        if pem_list:
            pem_file = ''
            for cert in pem_list:
                pem_file = f'{pem_file}-----BEGIN CERTIFICATE-----\n{textwrap.fill(cert, 64)}\n-----END CERTIFICATE-----\n'
        else:
            pem_file = None

        self.logger.debug('CAhandler._pem_cert_chain_generate() ended')
        return pem_file

    def _profile_id_get(self, csr: str) -> str:
        """ get profile id from csr """
        self.logger.debug('CAhandler._profile_id_get(%s)', csr)
        profile_id = None

        # parse profileid from http_header
        header_info = header_info_get(self.logger, csr=csr)
        if header_info:
            try:
                header_info_dic = json.loads(header_info[-1]['header_info'])
                if self.header_info_field in header_info_dic:
                    for ele in header_info_dic[self.header_info_field].split(' '):
                        if 'profileid' in ele.lower():
                            profile_id = ele.split('=')[1]
                            break
            except Exception as err:
                self.logger.error('CAhandler._profile_id_get() could not parse profile_id: %s', err)

        self.logger.debug('CAhandler._profile_id_get() ended with: %s', profile_id)
        return profile_id

    def _request_poll(self, request_url: str) -> Tuple[str, str, str, str, bool]:
        """ poll request """
        self.logger.debug('CAhandler._request_poll(%s)', request_url)

        error = None
        cert_bundle = None
        cert_raw = None
        poll_identifier = request_url
        rejected = False

        try:
            request_dic = requests.get(request_url, auth=self.auth, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        except Exception as err:
            self.logger.error('CAhandler._request.poll() returned: %s', err)
            request_dic = {}

        # check response
        if 'status' in request_dic:
            if request_dic['status'] == 'accepted':
                (error, cert_bundle, cert_raw) = self._api_poll(request_dic)
            elif request_dic['status'] == 'rejected':
                error = 'Request rejected by operator'
                rejected = True
            else:
                error = f'Unknown request status: {request_dic['status']}'
        else:
            error = '"status" field not found in response.'

        self.logger.debug('CAhandler._request_poll() ended with error: %s', error)
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def _trigger_bundle_build(self, cert_raw: str, ca_dic: Dict[str, str]) -> Tuple[str, str]:
        self.logger.debug('CAhandler._trigger_bundle_build()')
        error = None
        cert_bundle = None

        # get serial from pem file
        serial = cert_serial_get(self.logger, cert_raw)
        if serial:
            # get certificate information via rest by search for ca+ serial
            cert_list = self._cert_get_properties(serial, ca_dic['href'])
            # the first entry is the cert we are looking for
            if 'certificates' in cert_list and len(cert_list['certificates'][0]) > 0:
                cert_dic = cert_list['certificates'][0]
                cert_bundle = self._pem_cert_chain_generate(cert_dic)
            else:
                error = 'no certifcates found in rest query'
        else:
            error = 'serial number lookup via rest failed'

        self.logger.debug('CAhandler._trigger_bundle_build() ended with:  %s', error)
        return (error, cert_bundle)

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """ enroll certificate """
        self.logger.debug('Certificate.enroll()')
        cert_bundle = None
        error = None
        cert_raw = None
        poll_identifier = None

        cert_dic = self._cert_get(csr)

        if cert_dic:
            if 'status' in cert_dic:
                # this is an error
                if 'message' in cert_dic:
                    error = cert_dic['message']
                else:
                    error = 'unknown errror'
            elif 'certificateBase64' in cert_dic:
                # this is a valid cert generate the bundle
                cert_bundle = self._pem_cert_chain_generate(cert_dic)
                cert_raw = cert_dic['certificateBase64']
            elif 'href' in cert_dic:
                # request is pending
                (error, cert_bundle, cert_raw, poll_identifier) = self._loop_poll(cert_dic['href'])
            else:
                error = 'no certificate information found'
        else:
            error = 'internal error'
        self.logger.debug('Certificate.enroll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier)

    def poll(self, cert_name: str, poll_identifier: str, _csr: str) -> Tuple[str, str, str, str, str, bool]:
        """ poll pending status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = None
        cert_bundle = None
        cert_raw = None
        rejected = False

        if poll_identifier:
            (error, cert_bundle, cert_raw, poll_identifier, rejected) = self._request_poll(poll_identifier)
        else:
            self.logger.debug('skipping cert: %s as there is no poll_identifier', cert_name)

        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, cert: str, rev_reason: str = 'unspecified', rev_date: str = uts_to_date_utc(uts_now())) -> Tuple[int, str, str]:
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke(%s: %s)', rev_reason, rev_date)

        # get error message
        err_dic = error_dic_get(self.logger)

        # lookup REST-PATH of issuing CA
        ca_dic = self._ca_get_properties('name', self.ca_name)
        if 'href' in ca_dic:
            # get serial from pem file
            serial = cert_serial_get(self.logger, cert)
            if serial:
                (code, message, detail) = self._certificate_revoke(serial, ca_dic, rev_reason, rev_date)
            else:
                code = 404
                message = err_dic['serverinternal']
                detail = 'failed to get serial number from cert'
        else:
            code = 404
            message = err_dic['serverinternal']
            detail = 'CA could not be found'

        return (code, message, detail)

    def trigger(self, payload: str) -> Tuple[str, str, str]:
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = None
        cert_bundle = None
        cert_raw = None

        if payload:
            # decode payload
            cert = b64_decode(self.logger, payload)
            try:
                # cert is a base64 encoded pem object
                cert_raw = b64_encode(self.logger, cert_pem2der(cert))
            except Exception:
                # cert is a binary der encoded object
                cert_raw = b64_encode(self.logger, cert)

            # lookup REST-PATH of issuing CA
            ca_dic = self._ca_get_properties('name', self.ca_name)
            if 'href' in ca_dic:
                (error, cert_bundle) = self._trigger_bundle_build(cert_raw, ca_dic)
            else:
                error = 'Cannot find CA'
        else:
            error = 'No payload given'

        self.logger.debug('CAhandler.trigger() ended with error: %s', error)
        return (error, cert_bundle, cert_raw)
