#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca handler for Insta Certifier via REST-API class """
from __future__ import print_function
import textwrap
import math
import time
import json
import os
import requests
from requests.auth import HTTPBasicAuth
# pylint: disable=C0209, E0401
from acme_srv.helper import load_config, cert_serial_get, uts_now, uts_to_date_utc, b64_decode, b64_encode, cert_pem2der, parse_url, proxy_check, error_dic_get


class CAhandler(object):
    """ CA  handler """

    def __init__(self, debug=None, logger=None):
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
        self.proxy = None

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

    def _api_poll(self, request_dic):
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

    def _api_post(self, url, data):
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
            self.logger.error('CAhandler._api_post() returned error: {0}'.format(err_))
            api_response = str(err_)

        return api_response

    def _ca_get(self, filter_key=None, filter_value=None):
        """ get list of CAs"""
        self.logger.debug('_ca_get({0}:{1})'.format(filter_key, filter_value))
        params = {}

        if filter_key:
            params['q'] = '{0}:{1}'.format(filter_key, filter_value)

        if self.api_host:
            try:
                api_response = requests.get(self.api_host + '/v1/cas', auth=self.auth, params=params, proxies=self.proxy, verify=self.ca_bundle, timeout=self.request_timeout).json()
            except Exception as err_:
                self.logger.error('CAhandler._ca_get() returned error: {0}'.format(str(err_)))
                api_response = {'status': 500, 'message': str(err_), 'statusMessage': 'Internal Server Error'}
        else:
            self.logger.error('CAhandler._ca_get(): api_host is misisng in configuration')
            api_response = {}
        self.logger.debug('CAhandler._ca_get() ended with: {0}'.format(api_response))
        return api_response

    def _ca_get_properties(self, filter_key, filter_value):
        """ get properties for a single CAs"""
        self.logger.debug('_ca_get_properties({0}:{1})'.format(filter_key, filter_value))
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
        self.logger.debug('CAhandler._ca_get_properties() ended with: {0}'.format(ca_dic))
        return ca_dic

    def _cert_get(self, csr):
        """ get certificate from CA """
        self.logger.debug('CAhandler._cert_get({0})'.format(csr))
        ca_dic = self._ca_get_properties('name', self.ca_name)
        cert_dic = {}

        if 'href' in ca_dic:
            data = {'ca': ca_dic['href'], 'pkcs10': csr}
            cert_dic = self._api_post(self.api_host + '/v1/requests', data)

        if not cert_dic:
            cert_dic = ca_dic

        self.logger.debug('CAhandler._cert_get() ended with: {0}'.format(cert_dic))
        return cert_dic

    def _cert_get_properties(self, serial, ca_link):
        """ get properties for a single cert """
        self.logger.debug('_cert_get_properties({0}: {1})'.format(serial, ca_link))

        params = {'q': 'issuer-id:{0},serial-number:{1}'.format(ca_link, serial)}
        try:
            api_response = requests.get(self.api_host + '/v1/certificates', auth=self.auth, params=params, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        except Exception as err_:
            self.logger.error('CAhandler._cert_get_properties() returned error: {0}'.format(str(err_)))
            api_response = {'status': 500, 'message': str(err_), 'statusMessage': 'Internal Server Error'}
        self.logger.debug('CAhandler._cert_get_properties() ended')
        return api_response

    def _certificate_revoke(self, serial, ca_dic, rev_reason, rev_date):
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

    def _config_user_load(self, config_dic):
        """ load username """
        self.logger.debug('_config_user_load()')
        if 'api_user' in config_dic['CAhandler'] or 'api_user_variable' in config_dic['CAhandler']:
            if 'api_user_variable' in config_dic['CAhandler']:
                try:
                    self.api_user = os.environ[config_dic['CAhandler']['api_user_variable']]
                except Exception as err:
                    self.logger.error('CAhandler._config_load() could not load user_variable:{0}'.format(err))
            if 'api_user' in config_dic['CAhandler']:
                if self.api_user:
                    self.logger.info('CAhandler._config_load() overwrite api_user')
                self.api_user = config_dic['CAhandler']['api_user']
        else:
            self.logger.error('CAhandler._config_load() configuration incomplete: "api_user" parameter is missing in config file')

        self.logger.debug('_config_user_load() ended')

    def _config_password_load(self, config_dic):
        """ load password """
        self.logger.debug('_config_password_load()')

        if 'api_password' in config_dic['CAhandler'] or 'api_password_variable' in config_dic['CAhandler']:
            if 'api_password_variable' in config_dic['CAhandler']:
                try:
                    self.api_password = os.environ[config_dic['CAhandler']['api_password_variable']]
                except Exception as err:
                    self.logger.error('CAhandler._config_load() could not load passphrase_variable:{0}'.format(err))
            if 'api_password' in config_dic['CAhandler']:
                if self.api_password:
                    self.logger.info('CAhandler._config_load() overwrite api_password_variable')
                self.api_password = config_dic['CAhandler']['api_password']
        else:
            self.logger.error('CAhandler._config_load() configuration incomplete: "api_password" parameter is missing in config file')

        self.logger.debug('_config_password_load() ended')

    def _config_parameter_load(self, config_dic):
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

        # check if we get a ca bundle for verification
        if 'ca_bundle' in config_dic['CAhandler']:
            try:
                self.ca_bundle = config_dic.getboolean('CAhandler', 'ca_bundle')
            except Exception:
                self.ca_bundle = config_dic['CAhandler']['ca_bundle']

        self.logger.debug('_config_parameter_load() ended')

    def _config_proxy_load(self, config_dic):
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
                self.logger.warning('Challenge._config_load() proxy_server_list failed with error: {0}'.format(err_))

        self.logger.debug('_config_proxy_load() ended')

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

        # load proxy configuration
        self._config_proxy_load(config_dic)

        self.logger.debug('CAhandler._config_load() ended')

    def _poll_cert_get(self, request_dic, poll_identifier, error):
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

    def _loop_poll(self, request_url):
        """ poll request """
        self.logger.debug('CAhandler._loop_poll({0})'.format(request_url))

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

        self.logger.debug('CAhandler._loop_poll() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw, poll_identifier)

    def _pem_list_cert_get(self, cert_dic):
        self.logger.debug('CAhandler._pem_list_cert_get()')
        if 'issuer' in cert_dic:
            self.logger.debug('issuer found: {0}'.format(cert_dic['issuer']))
            ca_cert_dic = requests.get(cert_dic['issuer'], auth=self.auth, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        else:
            self.logger.debug('issuer found: {0}'.format(cert_dic['issuerCa']))
            ca_cert_dic = requests.get(cert_dic['issuerCa'], auth=self.auth, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()

        cert_dic = {}
        if 'certificates' in ca_cert_dic:
            if 'active' in ca_cert_dic['certificates']:
                cert_dic = requests.get(ca_cert_dic['certificates']['active'], auth=self.auth, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()

        self.logger.debug('CAhandler._pem_list_cert_get() ended')
        return cert_dic

    def _pem_list_build(self, cert_dic):
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

    def _pem_cert_chain_generate(self, cert_dic):
        """ build certificate chain based """
        self.logger.debug('CAhandler._pem_cert_chain_generate()')

        if cert_dic:
            pem_list = self._pem_list_build(cert_dic)
        else:
            pem_list = []

        if pem_list:
            pem_file = ''
            for cert in pem_list:
                pem_file = '{0}-----BEGIN CERTIFICATE-----\n{1}\n-----END CERTIFICATE-----\n'.format(pem_file, textwrap.fill(cert, 64))
        else:
            pem_file = None

        self.logger.debug('CAhandler._pem_cert_chain_generate() ended')
        return pem_file

    def _request_poll(self, request_url):
        """ poll request """
        self.logger.debug('CAhandler._request_poll({0})'.format(request_url))

        error = None
        cert_bundle = None
        cert_raw = None
        poll_identifier = request_url
        rejected = False

        try:
            request_dic = requests.get(request_url, auth=self.auth, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        except Exception as err:
            self.logger.error('CAhandler._request.poll() returned: {0}'.format(err))
            request_dic = {}

        # check response
        if 'status' in request_dic:
            if request_dic['status'] == 'accepted':
                (error, cert_bundle, cert_raw) = self._api_poll(request_dic)
            elif request_dic['status'] == 'rejected':
                error = 'Request rejected by operator'
                rejected = True
            else:
                error = 'Unknown request status: {0}'.format(request_dic['status'])
        else:
            error = '"status" field not found in response.'

        self.logger.debug('CAhandler._request_poll() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def _trigger_bundle_build(self, cert_raw, ca_dic):
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

        self.logger.debug('CAhandler._trigger_bundle_build() ended with:  {0}'.format(error))
        return (error, cert_bundle)

    def enroll(self, csr):
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

    def poll(self, cert_name, poll_identifier, _csr):
        """ poll pending status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = None
        cert_bundle = None
        cert_raw = None
        rejected = False

        if poll_identifier:
            (error, cert_bundle, cert_raw, poll_identifier, rejected) = self._request_poll(poll_identifier)
        else:
            self.logger.debug('skipping cert: {0} as there is no poll_identifier'.format(cert_name))

        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, cert, rev_reason='unspecified', rev_date=uts_to_date_utc(uts_now())):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke({0}: {1})'.format(rev_reason, rev_date))

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

    def trigger(self, payload):
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

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
