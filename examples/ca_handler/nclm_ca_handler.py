#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca handler for "NetGuard Certificate Lifecycle Manager" via REST-API class """
from __future__ import print_function
import os
import time
import json
import requests
# pylint: disable=C0209, E0401, R0913
from acme_srv.helper import load_config, build_pem_file, csr_cn_get, b64_encode, b64_url_recode, convert_string_to_byte, csr_san_get, cert_serial_get, date_to_uts_utc, uts_now, parse_url, proxy_check, error_dic_get


class CAhandler(object):
    """ CA  handler """

    def __init__(self, _debug=None, logger=None):
        self.logger = logger
        self.api_host = None
        self.ca_bundle = True
        self.credential_dic = {'api_user': None, 'api_password': None}
        self.tsg_info_dic = {'name': None, 'id': None}
        self.endpoint_dic = {'tsg': '/targetsystemgroups/'}
        self.template_info_dic = {'name': None, 'id': None}
        self.request_delta_treshold = 300
        self.headers = None
        self.ca_name = None
        self.error = None
        self.wait_interval = 5
        self.proxy = None
        self.request_timeout = 20

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.api_host:
            self._config_load()
            self._config_check()
        if not self.headers and not self.error:
            self._login()
        if not self.tsg_info_dic['id'] and not self.error:
            self._tsg_id_lookup()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _api_post(self, url, data):
        """  generic wrapper for an API post call """
        self.logger.debug('CAhandler._api_post()')
        try:
            api_response = requests.post(url=url, json=data, headers=self.headers, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        except Exception as err_:
            self.logger.error('CAhandler._api_post() returned error: {0}'.format(err_))
            api_response = str(err_)

        self.logger.debug('CAhandler._api_post() ended with: {0}'.format(api_response))
        return api_response

    def _ca_id_lookup(self):
        """ lookup CA ID based on CA_name """
        self.logger.debug('CAhandler._ca_id_lookup()')
        # query CAs
        ca_list = requests.get(self.api_host + '/ca?freeText=' + str(self.ca_name), headers=self.headers, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        ca_id = None
        if 'CAs' in ca_list:
            for ca_cert in ca_list['CAs']:
                # compare name or description field against config value
                if ('name' in ca_cert and ca_cert['name'] == self.ca_name) or ('desc' in ca_cert and ca_cert['desc'] == self.ca_name):
                    if 'id' in ca_cert:
                        ca_id = ca_cert['id']
        else:
            # log error
            self.logger.error('ca_id.lookup() no CAs found in response ...')

        if not ca_id:
            # log error
            self.logger.error('_ca_id_lookup(): no ca id found for {0}'.format(self.ca_name))
        self.logger.debug('CAhandler._ca_id_lookup() ended with: {0}'.format(ca_id))
        return ca_id

    def _ca_id_get(self, ca_list):
        """ get ca_id """
        self.logger.debug('CAhandler._ca_id_get()')
        ca_id = None
        if 'items' in ca_list['ca']:
            for ca_ in ca_list['ca']['items']:
                # compare name or description field against config value
                if ('displayName' in ca_ and ca_['displayName'] == self.ca_name):
                    # pylint: disable=R1723
                    if 'policyLinkId' in ca_:
                        ca_id = ca_['policyLinkId']
                        break
                    else:
                        self.logger.error('ca_id.lookup() policyLinkId field is missing  ...')

        self.logger.debug('CAhandler._ca_id_get() with {0}'.format(ca_id))
        return ca_id

    def _ca_policylink_id_lookup(self):
        """ lookup CA ID based on CA_name """
        self.logger.debug('CAhandler._ca_policylink_id_lookup()')

        # query CAs
        ca_list = requests.get(self.api_host + '/policy/ca?entityRef=CONTAINER&entityId={0}&allowedOnly=true&withTemplateById=0&enrollWithImportedCSR=true&csrHasPrivateKey=false&csrTemplateVersion=0'.format(self.tsg_info_dic['id']), headers=self.headers, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        ca_id = None
        if 'ca' in ca_list:
            ca_id = self._ca_id_get(ca_list)
        else:
            # log error
            self.logger.error('ca_id.lookup() no CAs found in response ...')

        if not ca_id:
            # log error
            self.logger.error('CAhandler_ca_policylink_id_lookup(): no policylink id found for {0}'.format(self.ca_name))
        self.logger.debug('CAhandler._ca_policylink_id_lookup() ended with: {0}'.format(ca_id))
        return ca_id

    def _cert_bundle_get(self, cert_dic, count, cert_id, cert_raw, cert_bundle, issuer_loop, error):
        """ get ca bundle """
        self.logger.debug('CAhandler._cert_bundle_get()')
        if count == 1:
            if 'der' in cert_dic['certificate']:
                cert_raw = cert_dic['certificate']['der']
            else:
                error = 'no der certificate returned for id {0}'.format(cert_id)
                self.logger.error('CAhandler._cert_bundle_build(): no der certificate returned for id: {0}'.format(cert_id))

        if 'pem' in cert_dic['certificate']:
            cert_bundle = '{0}{1}'.format(cert_bundle, cert_dic['certificate']['pem'])
        else:
            error = 'no pem certificate returned for id {0}'.format(cert_id)
            self.logger.error('CAhandler._cert_bundle_build(): no pem certificate returned for id: {0}'.format(cert_id))

        if 'issuerInfo' in cert_dic['certificate']:
            if 'id' in cert_dic['certificate']['issuerInfo'] and cert_dic['certificate']['issuerInfo']['id'] != cert_id:
                self.logger.debug('CAhandler._cert_bundle_build() fetch certificate for certid: {0}'.format(cert_dic['certificate']['issuerInfo']['id']))
                cert_id = cert_dic['certificate']['issuerInfo']['id']
                issuer_loop = True

        self.logger.debug('CAhandler._cert_bundle_get() ended with: {0}'.format(cert_id))
        return (error, cert_raw, cert_bundle, issuer_loop, cert_id)

    def _cert_bundle_build(self, cert_id):
        """ download cert and create bundle """
        self.logger.debug('CAhandler._cert_bundle_build({0})'.format(cert_id))
        cert_bundle = ''
        error = None
        cert_raw = None
        issuer_loop = True
        count = 0

        while issuer_loop:
            # set issuer loop to False to avoid ending in an endless loop
            issuer_loop = False
            count += 1
            self.logger.debug('CAhandler._cert_bundle_build() fetch certificate for certid: {0}'.format(cert_id))

            cert_dic = requests.get(self.api_host + '/certificates/' + str(cert_id), headers=self.headers, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
            if 'certificate' in cert_dic:
                (error, cert_raw, cert_bundle, issuer_loop, cert_id) = self._cert_bundle_get(cert_dic, count, cert_id, cert_raw, cert_bundle, issuer_loop, error)
            else:
                self.logger.error('CAhandler._cert_bundle_build(): invalid reponse returned for id: {0}'.format(cert_id))
                error = 'invalid reponse returned for id: {0}'.format(cert_id)

        # we need this for backwards compability
        if cert_bundle == '':
            cert_bundle = None

        self.logger.debug('CAhandler._cert_bundle_build() ended')
        return (error, cert_bundle, cert_raw)

    def _cert_list_fetch(self, url):
        """ fetch certificate list and consider pagination """
        self.logger.debug('CAhandler._cert_list_fetch({0})'.format(url))

        cert_list = []
        while url:
            try:
                _tmp_cert_list = requests.get(url, headers=self.headers, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
            except Exception as err_:
                self.logger.error('CAhandler._cert_list_fetch() returned error: {0}'.format(str(err_)))
                _tmp_cert_list = []

            if 'certificates' in _tmp_cert_list:
                cert_list.extend(_tmp_cert_list['certificates'])
                if 'next' in _tmp_cert_list and _tmp_cert_list['next']:
                    url = self.api_host + _tmp_cert_list['next']
                else:
                    url = None
            else:
                url = None

        self.logger.debug('CAhandler._cert_list_fetch() ended with {0} entries'.format(len(cert_list)))
        return cert_list

    def _cert_list_lookup(self, csr_cn):
        """ get certificates """
        self.logger.debug('CAhandler._cert_list_lookup({0})'.format(csr_cn))

        try:
            if csr_cn:
                url = self.api_host + '/certificates?freeText==' + str(csr_cn) + '&stateCurrent=false&stateHistory=false&stateWaiting=false&stateManual=false&stateUnattached=false&expiresAfter=%22%22&expiresBefore=%22%22&sortAttribute=createdAt&sortOrder=desc&containerId=' + str(self.tsg_info_dic['id'])
            else:
                url = self.api_host + '/certificates?stateCurrent=false&stateHistory=false&stateWaiting=false&stateManual=false&stateUnattached=false&expiresAfter=%22%22&expiresBefore=%22%22&sortAttribute=createdAt&sortOrder=desc&containerId=' + str(self.tsg_info_dic['id'])
            cert_list = self._cert_list_fetch(url)
        except Exception as err_:
            self.logger.error('CAhandler._cert_id_lookup() returned error: {0}'.format(str(err_)))
            cert_list = []

        self.logger.debug('CAhandler._cert_list_lookup() ended')
        return cert_list

    def _cert_id_get(self, cert_list, san_list):
        """ lookup certificate id from certificate_list """
        self.logger.debug('CAhandler._cert_id_get()')
        cert_id = None
        for cert in sorted(cert_list, key=lambda i: i['certificateId'], reverse=True):
            # lets compare the SAN (this is more reliable than comparing the CN (certbot does not set a CN
            if san_list and 'subjectAltName' in cert:
                result = self._san_compare(san_list, cert['subjectAltName'])
                if result and 'certificateId' in cert:
                    cert_id = cert['certificateId']
                    break

        self.logger.debug('CAhandler._cert_id_get() ended')
        return cert_id

    def _cert_id_lookup(self, csr_cn, san_list=None):
        """ lookup cert id based on CN """
        self.logger.debug('CAhandler._cert_id_lookup({0}:{1})'.format(csr_cn, san_list))

        # get certificate list having the csr cn
        cert_list = self._cert_list_lookup(csr_cn)

        cert_id = None
        if cert_list:
            try:
                cert_id = self._cert_id_get(cert_list, san_list)
            except Exception as err_:
                self.logger.error('_cert_id_lookup(): response incomplete: {0}'.format(err_))
        else:
            self.logger.error('_cert_id_lookup(): no certificates found for {0}'.format(csr_cn))

        self.logger.debug('CAhandler._cert_id_lookup() ended with: {0}'.format(cert_id))
        return cert_id

    def _config_api_access_check(self):
        """ check config for consitency """
        self.logger.debug('CAhandler._config_api_access_check()')

        if not self.api_host:
            self.logger.error('"api_host" to be set in config file')
            self.error = 'api_host to be set in config file'

        if not self.error:
            if not bool('api_user' in self.credential_dic and bool(self.credential_dic['api_user'])):
                self.logger.error('"api_user" to be set in config file')
                self.error = 'api_user to be set in config file'

        if not self.error:
            if not bool('api_password' in self.credential_dic and bool(self.credential_dic['api_password'])):
                self.logger.error('"api_password" to be set in config file')
                self.error = 'api_password to be set in config file'

        self.logger.debug('CAhandler._config_api_access_check() ended')

    def _config_names_check(self):
        """ check config for consitency """
        self.logger.debug('CAhandler._config_names_check()')

        if not self.error:
            if not bool('name' in self.tsg_info_dic and bool(self.tsg_info_dic['name'])):
                self.logger.error('"tsg_name" to be set in config file')
                self.error = 'tsg_name to be set in config file'

        if not self.error and not self.ca_name:
            self.logger.error('"ca_name" to be set in config file')
            self.error = 'ca_name to be set in config file'

        if not self.error and self.ca_bundle is False:
            self.logger.warning('"ca_bundle" set to "False" - validation of server certificate disabled')

        self.logger.debug('CAhandler._config_names_check() ended')

    def _config_check(self):
        """ check config for consitency """
        self.logger.debug('CAhandler._config_check()')

        self._config_api_access_check()
        self._config_names_check()

        self.logger.debug('CAhandler._config_check() ended')

    def _config_api_user_load(self, config_dic):
        """ load user """
        self.logger.debug('CAhandler._config_api_user_load()')

        if 'api_user_variable' in config_dic['CAhandler']:
            try:
                self.credential_dic['api_user'] = os.environ[config_dic['CAhandler']['api_user_variable']]
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load user_variable:{0}'.format(err))
        if 'api_user' in config_dic['CAhandler']:
            if self.credential_dic['api_user']:
                self.logger.info('CAhandler._config_load() overwrite api_user')
            self.credential_dic['api_user'] = config_dic['CAhandler']['api_user']

        self.logger.debug('CAhandler._config_api_user_load() ended.')

    def _config_api_password_load(self, config_dic):
        """ load password """
        self.logger.debug('CAhandler._config_api_password_load()')

        if 'api_password_variable' in config_dic['CAhandler']:
            try:
                self.credential_dic['api_password'] = os.environ[config_dic['CAhandler']['api_password_variable']]
            except Exception as err:
                self.logger.error('CAhandler._config_load() could not load password_variable:{0}'.format(err))
        if 'api_password' in config_dic['CAhandler']:
            if self.credential_dic['api_password']:
                self.logger.info('CAhandler._config_load() overwrite api_password')
            self.credential_dic['api_password'] = config_dic['CAhandler']['api_password']

        self.logger.debug('CAhandler._config_api_password_load() ended')

    def _config_names_load(self, config_dic):
        """ load names from config"""
        self.logger.debug('CAhandler._config_names_load()')

        if 'api_host' in config_dic['CAhandler']:
            self.api_host = config_dic['CAhandler']['api_host']

        if 'ca_name' in config_dic['CAhandler']:
            self.ca_name = config_dic['CAhandler']['ca_name']

        if 'tsg_name' in config_dic['CAhandler']:
            self.tsg_info_dic['name'] = config_dic['CAhandler']['tsg_name']

        if 'template_name' in config_dic['CAhandler']:
            self.template_info_dic['name'] = config_dic['CAhandler']['template_name']

        self.logger.debug('CAhandler._config_names_load() ended')

    def _config_proxy_load(self, config_dic):
        """ load proxy configuration """
        self.logger.debug('CAhandler._config_proxy_load()')

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

        self.logger.debug('CAhandler._config_proxy_load() ended')

    def _config_timer_load(self, config_dic):
        """ load timer """
        self.logger.debug('CAhandler._config_proxy_load()')

        if 'request_delta_treshold' in config_dic['CAhandler']:
            try:
                self.request_delta_treshold = int(config_dic['CAhandler']['request_delta_treshold'])
            except Exception:
                self.logger.error('CAhandler._config_load() could not load request_delta_treshold:{0}'.format(config_dic['CAhandler']['request_delta_treshold']))

        # check if we get a ca bundle for verification
        if 'ca_bundle' in config_dic['CAhandler']:
            try:
                self.ca_bundle = config_dic.getboolean('CAhandler', 'ca_bundle')
            except Exception:
                self.ca_bundle = config_dic['CAhandler']['ca_bundle']

        if 'request_timeout' in config_dic['CAhandler']:
            try:
                self.request_timeout = int(config_dic['CAhandler']['request_timeout'])
            except Exception:
                self.request_timeout = 20

        self.logger.debug('CAhandler._config_proxy_load() ended')

    def _config_load(self):
        """" load config from file """
        # pylint: disable=r0912
        self.logger.debug('CAhandler._config_load()')
        config_dic = load_config(self.logger, 'CAhandler')
        if 'CAhandler' in config_dic:

            self._config_names_load(config_dic)
            self._config_api_user_load(config_dic)
            self._config_api_password_load(config_dic)
            self._config_timer_load(config_dic)

        self._config_proxy_load(config_dic)

        self.logger.debug('CAhandler._config_load() ended')

    def _lastrequests_get(self):
        """ last requests get """
        self.logger.debug('CAhandler._lastrequests_get()')

        req_all = []
        # special certbot scenario (no CN in CSR). No better idea how to handle this, take first request
        try:
            result = requests.get(self.api_host + '/requests', headers=self.headers, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
            if 'requests' in result:
                req_all = result['requests']
            else:
                self.logger.error('_lastrequests_get(): response incomplete:')
        except Exception as err_:
            self.logger.error('CAhandler._lastrequests_get() returned error: {0}'.format(str(err_)))

        self.logger.debug('CAhandler._lastrequests_get() endet with {0}'.format(len(req_all)))
        return req_all

    def _reqcn_lookup(self, req):
        self.logger.debug('CAhandler._reqcn_lookup()')

        req_cn = None
        if 'subjectName' in req:
            # split the subject and filter CN
            subject_list = req['subjectName'].split(',')
            for field in subject_list:
                field = field.strip()
                if field.startswith('CN='):
                    req_cn = field.lower().replace('cn=', '')
                    break

        self.logger.debug('CAhandler._reqcn_lookup() ended with: {0}'.format(req_cn))
        return req_cn

    def _reqid_from_last_requests(self, last_request_list, csr):
        """ get reqid """
        self.logger.debug('CAhandler._reqid_from_last_requests()')

        req_id = None
        for _req in sorted(last_request_list, key=lambda i: i['requestId'], reverse=True):
            if 'pkcs10' in _req and _req['pkcs10'] == csr:
                req_id = _req['requestId']
                break

        self.logger.debug('CAhandler._reqid_from_last_requests() ended with: {0}'.format(req_id))
        return req_id

    def _reqid_lookup(self, csr, csr_cn, uts_n, unused_request_list, last_request_list):
        """ lookup request """
        self.logger.debug('CAhandler._reqid_lookup()')

        req_id = None

        # check every CSR
        for req in sorted(unused_request_list, key=lambda i: i['requestID'], reverse=True):
            req_cn = None
            # check the import date and consider only csr which are less then 5min old
            csr_uts = date_to_uts_utc(req['addedAt'][:25], '%Y-%m-%dT%H:%M:%S.%f')
            if uts_n - csr_uts < self.request_delta_treshold:

                # get common name from requst
                req_cn = self._reqcn_lookup(req)

                if csr_cn:
                    if req_cn == csr_cn.lower() and 'requestID' in req:
                        req_id = req['requestID']
                        break
                else:
                    req_id = self._reqid_from_last_requests(last_request_list, csr)

        self.logger.debug('CAhandler._reqid_lookup() ended with: {0}'.format(req_id))
        return req_id

    def _csr_id_lookup(self, csr_cn, _csr_san_list, csr=None):
        """ lookup CSR based on CN """
        self.logger.debug('CAhandler._csr_id_lookup()')

        # uts
        uts_n = uts_now()

        # get unused requests from NCLM
        unused_request_list = self._unusedrequests_get()

        # get last 50 requests
        if not csr_cn:
            last_request_list = self._lastrequests_get()
        else:
            last_request_list = []

        try:
            req_id = self._reqid_lookup(csr, csr_cn, uts_n, unused_request_list, last_request_list)
        except Exception as err_:
            self.logger.error('_csr_id_lookup(): response incomplete: {0}'.format(err_))
            req_id = None

        self.logger.debug('CAhandler._csr_id_lookup() ended with: {0}'.format(req_id))
        return req_id

    def _login(self):
        """ _login into NCLM API """
        self.logger.debug('CAhandler._login()')
        # check first if API is reachable
        api_response = requests.get(self.api_host, proxies=self.proxy, timeout=self.request_timeout)
        self.logger.debug('api response code:{0}'.format(api_response.status_code))
        if api_response.ok:
            # all fine try to login
            self.logger.debug('log in to {0} as user "{1}"'.format(self.api_host, self.credential_dic['api_user']))
            data = {'username': self.credential_dic['api_user'], 'password': self.credential_dic['api_password']}
            api_response = requests.post(url=self.api_host + '/token?grant_type=client_credentials', json=data, proxies=self.proxy, timeout=self.request_timeout)
            if api_response.ok:
                json_dic = api_response.json()
                if 'access_token' in json_dic:
                    self.headers = {"Authorization": "Bearer {0}".format(json_dic['access_token'])}
                    _username = json_dic.get('username', None)
                    _realms = json_dic.get('realms', None)
                    self.logger.debug('login response:\n user: {0}\n token: {1}\n realms: {2}\n'.format(_username, json_dic['access_token'], _realms))
                else:
                    self.logger.error('CAhandler._login(): No token returned. Aborting...')
            else:
                self.logger.error('CAhandler._login() error during post: {0}'.format(api_response.status_code))
        else:
            # If response code is not ok (200), print the resulting http error code with description
            self.logger.error('CAhandler._login() error during get: {0}'.format(api_response.status_code))

    def _request_import(self, csr):
        """ import certificate request to NCLM """
        self.logger.debug('CAhandler._request_import()')
        data_dic = {'pkcs10': csr}
        try:
            result = self._api_post(self.api_host + self.endpoint_dic['tsg'] + str(self.tsg_info_dic['id']) + '/importrequest', data_dic)
        except Exception as err_:
            self.logger.error('CAhandler._request_import() returned error: {0}'.format(str(err_)))
            result = None
        return result

    def _unusedrequests_get(self):
        """ get unused requests """
        self.logger.debug('CAhandler.requests_get()')
        try:
            result = requests.get(self.api_host + self.endpoint_dic['tsg'] + str(self.tsg_info_dic['id']) + '/unusedrequests', headers=self.headers, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        except Exception as err_:
            self.logger.error('CAhandler._unusedrequests_get() returned error: {0}'.format(str(err_)))
            result = None
        return result

    def _san_compare(self, csr_san, cert_san):
        """ compare sans from csr with san in cert """
        self.logger.debug('CAhandler._san_compare({0}, {1})'.format(csr_san, cert_san))
        # convert csr_sans to lower case
        csr_san_lower = []
        for ele in csr_san:
            for san in ele.split(','):
                csr_san_lower.append(san.strip().lower())

        # build cert_san list in the same format as csr_san
        cert_san_lower = []
        for stype in cert_san:
            for san in cert_san[stype]:
                cert_san_lower.append('{0}:{1}'.format(stype.lower(), san.lower()))

        result = False

        # compare lists
        if sorted(csr_san_lower) == sorted(cert_san_lower):
            result = True

        self.logger.debug('CAhandler._san_compare() ended with: {0}'.format(result))
        return result

    def _template_list_get(self):
        """ get list of templates """
        self.logger.debug('CAhandler._template_id_lookup({0})'.format(self.tsg_info_dic['id']))
        try:
            template_list = requests.get(self.api_host + '/policy/ca/7/templates?entityRef=CONTAINER&entityId=' + str(self.tsg_info_dic['id']) + '&allowedOnly=true&enroll=true', headers=self.headers, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        except Exception as err_:
            self.logger.error('CAhandler._template_id_lookup() returned error: {0}'.format(err_))
            template_list = []

        return template_list

    def _templates_enumerate(self, template_list):
        """ get template id based on name """
        self.logger.debug('CAhandler._template_id_lookup() for template: {0}'.format(self.template_info_dic['name']))

        for template in template_list['template']['items']:
            if 'allowed' in template and template['allowed'] and 'linkType' in template and template['linkType'].lower() == 'template':
                if 'displayName' in template and template['displayName'] == self.template_info_dic['name']:
                    if 'policyLinkId' in template:
                        self.template_info_dic['id'] = template['policyLinkId']
                        break

    def _template_id_lookup(self):
        """ get template id based on name """
        self.logger.debug('CAhandler._template_id_lookup() for template: {0}'.format(self.template_info_dic['name']))

        # get list of templates
        template_list = self._template_list_get()

        # enumerate templates to get template-id
        if 'template' in template_list and 'items' in template_list['template']:
            self._templates_enumerate(template_list)
        else:
            self.logger.error('CAhandler._template_id_lookup() no templates found for filter: {0}...'.format(self.template_info_dic['name']))

        self.logger.debug('CAhandler._template_id_lookup() ended with: {0}'.format(str(self.template_info_dic['id'])))

    def _tsg_id_lookup(self):
        """ get target system id based on name """
        self.logger.debug('CAhandler._tsg_id_lookup() for tsg: {0}'.format(self.tsg_info_dic['name']))
        try:
            tsg_list = requests.get(self.api_host + '/targetsystemgroups?freeText=' + str(self.tsg_info_dic['name']) + '&offset=0&limit=50&fetchPath=true', headers=self.headers, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        except Exception as err_:
            self.logger.error('CAhandler._tsg_id_lookup() returned error: {0}'.format(err_))
            tsg_list = []
        if 'targetSystemGroups' in tsg_list:
            for tsg in tsg_list['targetSystemGroups']:
                if 'name' in tsg and 'id' in tsg:
                    if self.tsg_info_dic['name'] == tsg['name']:
                        self.tsg_info_dic['id'] = tsg['id']
                        break
                else:
                    self.logger.error('CAhandler._tsg_id_lookup() incomplete response: {0}'.format(tsg))
        else:
            self.logger.error('CAhandler._tsg_id_lookup() no target-system-groups found for filter: {0}...'.format(self.tsg_info_dic['name']))
        self.logger.debug('CAhandler._tsg_id_lookup() ended with: {0}'.format(str(self.tsg_info_dic['id'])))

    def _cert_enroll(self, csr, csr_cn, csr_san_list, policylink_id):
        """ enroll operation """
        self.logger.debug('CAhandler._cert_enroll()')

        error = None
        cert_bundle = None
        cert_raw = None

        # build_pem_file
        csr = build_pem_file(self.logger, None, csr, 64, True)
        csr = b64_encode(self.logger, convert_string_to_byte(csr))
        data_dic = {'allowDuplicateCn': True, 'request': {'pkcs10': csr}, 'ca': {'selectedId': policylink_id}}

        # add template if correctly configured
        if 'id' in self.template_info_dic and self.template_info_dic['id']:
            data_dic['template'] = {'selectedId': self.template_info_dic['id']}

        self._api_post(self.api_host + self.endpoint_dic['tsg'] + str(self.tsg_info_dic['id']) + '/enroll', data_dic)
        # wait for certificate enrollment to get finished
        time.sleep(self.wait_interval)
        cert_id = self._cert_id_lookup(csr_cn, csr_san_list)
        if cert_id:
            (error, cert_bundle, cert_raw) = self._cert_bundle_build(cert_id)
        else:
            error = 'certifcate id lookup failed for:  {0}, {1}'.format(csr_cn, csr_san_list)
            self.logger.error('CAhandler.eroll(): certifcate id lookup failed for:  {0}, {1}'.format(csr_cn, csr_san_list))

        return (error, cert_bundle, cert_raw)

    def enroll(self, csr):
        """ enroll certificate from NCLM """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        error = None
        cert_raw = None

        # recode csr
        csr = b64_url_recode(self.logger, csr)

        if not self.error:
            if self.tsg_info_dic['id']:

                # templating
                policylink_id = self._ca_policylink_id_lookup()
                if policylink_id and self.template_info_dic['name'] and not self.template_info_dic['id']:
                    self._template_id_lookup()

                # get common name of CSR
                csr_cn = csr_cn_get(self.logger, csr)
                csr_san_list = csr_san_get(self.logger, csr)

                if policylink_id and self.tsg_info_dic['id']:
                    # enroll operation
                    (error, cert_bundle, cert_raw) = self._cert_enroll(csr, csr_cn, csr_san_list, policylink_id)
                else:
                    error = 'enrollment aborted. policylink_id: {0}, tsg_id: {1}'.format(policylink_id, self.tsg_info_dic['id'])
                    self.logger.error('CAhandler.eroll(): enrollment aborted. policylink_id: {0}, tsg_id: {1}'.format(policylink_id, self.tsg_info_dic['id']))
            else:
                error = 'CAhandler.eroll(): ID lookup for targetSystemGroup "{0}" failed.'.format(self.tsg_info_dic['name'])
        else:
            self.logger.error(self.error)

        self.logger.debug('CAhandler.enroll() ended')
        return (error, cert_bundle, cert_raw, None)

    def poll(self, _cert_name, poll_identifier, _csr):
        """ poll status of pending CSR and download certificates """
        self.logger.debug('CAhandler.poll()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None
        rejected = False

        self.logger.debug('CAhandler.poll() ended')
        return (error, cert_bundle, cert_raw, poll_identifier, rejected)

    def revoke(self, cert, rev_reason, rev_date):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')
        # get serial from pem file and convert to formated hex
        serial = '0{:x}'.format(cert_serial_get(self.logger, cert))
        hex_serial = ':'.join(serial[i:i + 2] for i in range(0, len(serial), 2))

        # search for certificate
        try:
            cert_list = requests.get(self.api_host + '/certificates?freeText==' + str(hex_serial) + '&stateCurrent=false&stateHistory=false&stateWaiting=false&stateManual=false&stateUnattached=false&expiresAfter=%22%22&expiresBefore=%22%22&sortAttribute=createdAt&sortOrder=desc&containerId=' + str(self.tsg_info_dic['id']), headers=self.headers, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()
        except Exception as err_:
            self.logger.error('CAhandler.revoke(): request get aborted with err: {0}'.format(err_))
            cert_list = []

        err_dic = error_dic_get(self.logger)
        if 'certificates' in cert_list:
            try:
                cert_id = cert_list['certificates'][0]['certificateId']
                data_dic = {'reason': rev_reason, 'time': rev_date}
                try:
                    detail = self._api_post(self.api_host + '/certificates/' + str(cert_id) + '/revocationrequest', data_dic)
                    code = 200
                    message = None
                except Exception as err:
                    self.logger.error('CAhandler.revoke(): _api_post got aborted with err: {0}'.format(err))
                    code = 500
                    message = err_dic['serverinternal']
                    detail = 'Revocation operation failed'
            except Exception:
                code = 404
                message = err_dic['serverinternal']
                detail = 'CertificateID could not be found'
        else:
            code = 404
            message = err_dic['serverinternal']
            detail = 'Cert could not be found'

        return (code, message, detail)

    def trigger(self, _payload):
        """ process trigger message and return certificate """
        self.logger.debug('CAhandler.trigger()')

        error = 'Method not implemented.'
        cert_bundle = None
        cert_raw = None

        self.logger.debug('CAhandler.trigger() ended with error: {0}'.format(error))
        return (error, cert_bundle, cert_raw)
