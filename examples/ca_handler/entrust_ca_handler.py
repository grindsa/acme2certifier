# -*- coding: utf-8 -*-
""" CA handler using Digicert CertCentralAPI"""
from __future__ import print_function
from typing import Tuple, Dict
import json
import requests
# pylint: disable=e0401
from acme_srv.helper import load_config, csr_cn_get, cert_pem2der, b64_encode, allowed_domainlist_check, eab_profile_header_info_check, uts_now, uts_to_date_utc, cert_serial_get, config_eab_profile_load, config_headerinfo_load, csr_san_get


CONTENT_TYPE = 'application/json'


class CAhandler(object):
    """ Digicert CertCentralAP handler """

    def __init__(self, _debug: bool = None, logger: object = None):
        self.logger = logger
        self.api_url = ''
        self.api_key = 'foo'

        self.allowed_domainlist = []
        self.header_info_field = False
        self.eab_handler = None
        self.eab_profiling = False

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.api_key:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _allowed_domainlist_check(self, csr: str) -> str:
        """ check allowed domainlist """
        self.logger.debug('CAhandler._allowed_domainlist_check()')

        error = None
        # check CN and SAN against black/whitlist
        if self.allowed_domainlist:
            # check sans / cn against list of allowed comains from config
            result = allowed_domainlist_check(self.logger, csr, self.allowed_domainlist)
            if not result:
                error = 'Either CN or SANs are not allowed by configuration'

        self.logger.debug('CAhandler._allowed_domainlist_check() ended with %s', error)
        return error

    def _api_get(self, url: str) -> Tuple[int, Dict[str, str]]:
        """ post data to API """
        self.logger.debug('CAhandler._api_get()')
        headers = {
            'X-DC-DEVKEY': self.api_key,
            'Content-Type': CONTENT_TYPE
        }

        try:
            api_response = requests.get(url=url, headers=headers, proxies=self.proxy, timeout=self.request_timeout)
            code = api_response.status_code
            try:
                content = api_response.json()
            except Exception as err_:
                self.logger.error('CAhandler._api_get() returned error during json parsing: %s', err_)
                content = str(err_)
        except Exception as err_:
            self.logger.error('CAhandler._api_get() returned error: %s', err_)
            code = 500
            content = str(err_)

        return code, content

    def _api_post(self, url: str, data: Dict[str, str]) -> Tuple[int, Dict[str, str]]:
        """ post data to API """
        self.logger.debug('CAhandler._api_post()')
        headers = {
            'X-DC-DEVKEY': self.api_key,
            'Content-Type': CONTENT_TYPE
        }

        try:
            api_response = requests.post(url=url, headers=headers, json=data, proxies=self.proxy, timeout=self.request_timeout)
            code = api_response.status_code
            if api_response.text:
                try:
                    content = api_response.json()
                except Exception as err_:
                    self.logger.error('CAhandler._api_post() returned error during json parsing: %s', err_)
                    content = str(err_)
            else:
                content = None
        except Exception as err_:
            self.logger.error('CAhandler._api_post() returned error: %s', err_)
            code = 500
            content = str(err_)

        return code, content

    def _api_put(self, url: str, data: Dict[str, str]) -> Tuple[int, Dict[str, str]]:
        """ post data to API """
        self.logger.debug('CAhandler._api_put()')
        headers = {
            'X-DC-DEVKEY': self.api_key,
            'Content-Type': CONTENT_TYPE
        }

        try:
            api_response = requests.put(url=url, headers=headers, json=data, proxies=self.proxy, timeout=self.request_timeout)
            code = api_response.status_code
            if api_response.text:
                try:
                    content = api_response.json()
                except Exception as err_:
                    self.logger.error('CAhandler._api_put() returned error during json parsing: %s', err_)
                    content = str(err_)
            else:
                content = None
        except Exception as err_:
            self.logger.error('CAhandler._api_put() returned error: %s', err_)
            code = 500
            content = str(err_)

        return code, content

    def _config_check(self) -> str:
        """ check config """
        self.logger.debug('CAhandler._config_check()')

        error = None
        for ele in ['api_url', 'api_key', 'organization_name']:
            if not getattr(self, ele):
                error = f'{ele} parameter in missing in config file'
                self.logger.error('CAhandler._config_check() ended with error: %s', error)
                break

        self.logger.debug('CAhandler._config_check() ended with: %s', error)
        return error

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')

        config_dic = load_config(self.logger, 'CAhandler')
        if 'CAhandler' in config_dic:
            cfg_dic = dict(config_dic['CAhandler'])
            self.api_url = cfg_dic.get('api_url', 'https://www.digicert.com/services/v2/')
            self.api_key = cfg_dic.get('api_key', None)
            self.cert_type = cfg_dic.get('cert_type', 'ssl_basic')
            self.signature_hash = cfg_dic.get('signature_hash', 'sha256')
            self.order_validity = cfg_dic.get('order_validity', 1)
            self.request_timeout = cfg_dic.get('request_timeout', 10)
            self.organization_id = cfg_dic.get('organization_id', None)
            self.organization_name = cfg_dic.get('organization_name', None)

            if 'allowed_domainlist' in config_dic['CAhandler']:
                try:
                    self.allowed_domainlist = json.loads(config_dic['CAhandler']['allowed_domainlist'])
                except Exception as err:
                    self.logger.error('CAhandler._config_load(): failed to parse allowed_domainlist: %s', err)
                    self.allowed_domainlist = 'failed to parse'

        # load profiling
        self.eab_profiling, self.eab_handler = config_eab_profile_load(self.logger, config_dic)
        # load header info
        self.header_info_field = config_headerinfo_load(self.logger, config_dic)

        self.logger.debug('CAhandler._config_load() ended')


    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """ enroll certificate  """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None

        # check configuration
        error = self._config_check()

        if not error:
            pass

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

    def revoke(self, certificate_raw: str, _rev_reason: str = 'unspecified', _rev_date: str = uts_to_date_utc(uts_now())) -> Tuple[int, str, str]:
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke()')

        code = None
        message = None
        detail = 'Method not implemented.'

        self.logger.debug('CAhandler.poll() ended')

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
