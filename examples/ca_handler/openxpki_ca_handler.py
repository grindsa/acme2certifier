# -*- coding: utf-8 -*-
""" openxpki rpc ca handler """
import math
import time
import os
from typing import Tuple, Dict
import requests
from requests_pkcs12 import Pkcs12Adapter
# pylint: disable=e0401
from acme_srv.helper import load_config, build_pem_file, cert_pem2der, b64_url_recode, b64_encode, error_dic_get, config_allowed_domainlist_load, allowed_domainlist_check
from acme_srv.db_handler import DBstore


class CAhandler(object):
    """ ejbca rest handler class """

    def __init__(self, _debug: bool = None, logger: object = None):
        self.logger = logger
        self.host = None
        self.ca_bundle = True
        self.proxy = None
        self.request_timeout = 5
        self.session = None
        self.cert_profile_name = None
        self.client_cert = None
        self.cert_passphrase = None
        self.endpoint_name = None
        self.polling_timeout = 0
        self.rpc_path = '/rpc/'
        self.err_msg_dic = error_dic_get(self.logger)
        self.dbstore = DBstore(False, self.logger)
        self.allowed_domainlist = []

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.host:
            self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _cert_bundle_create(self, response: Dict[str, str]) -> Tuple[str, str, str]:
        """ format bundle """
        error = None
        cert_bundle = None
        cert_raw = None

        if 'data' in response and 'certificate' in response['data'] and 'chain' in response['data']:
            # create base65 encoded der file
            cert_raw = b64_encode(self.logger, cert_pem2der(response['data']['certificate']))
            cert_bundle = f'{response["data"]["certificate"]}\n{response["data"]["chain"]}'
        else:
            error = 'Malformed response'
            self.logger.error('CAhandler._cert_bundle_create() returned malformed response: %s', response)

        return (error, cert_bundle, cert_raw)

    def _cert_identifier_get(self, cert_raw: str) -> str:
        """ get cert_identifier """
        self.logger.debug('CAhandler._cert_identifier_get()')

        cert_identifier = None
        result = self.dbstore.certificate_lookup('cert_raw', cert_raw, vlist=('name', 'poll_identifier'))
        if 'poll_identifier' in result and result['poll_identifier']:
            cert_identifier = result['poll_identifier']

        self.logger.debug('CAhandler._cert_identifier_get() ended with: %s', cert_identifier)
        return cert_identifier

    def _config_server_load(self, config_dic):
        """ load server information """
        self.logger.debug('CAhandler._config_auth_load()')

        if 'CAhandler' in config_dic:
            if 'host' in config_dic['CAhandler']:
                self.host = config_dic['CAhandler']['host']

            if 'endpoint_name' in config_dic['CAhandler']:
                self.endpoint_name = config_dic['CAhandler']['endpoint_name']

            if 'request_timeout' in config_dic['CAhandler']:
                self.request_timeout = config_dic['CAhandler']['request_timeout']

            if 'rpc_path' in config_dic['CAhandler']:
                self.rpc_path = config_dic['CAhandler']['rpc_path']

        self.logger.debug('CAhandler._config_server_load() ended')

    def _config_ca_load(self, config_dic):
        """ load ca information """
        self.logger.debug('CAhandler._config_ca_load()')
        if 'CAhandler' in config_dic:

            if 'ca_bundle' in config_dic['CAhandler']:
                try:
                    self.ca_bundle = config_dic.getboolean('CAhandler', 'ca_bundle')
                except Exception as err:
                    self.logger.debug('CAhandler._config_server_load(): failed to load ca_bundle option: %s', err)
                    self.ca_bundle = config_dic['CAhandler']['ca_bundle']

            if 'cert_profile_name' in config_dic['CAhandler']:
                self.cert_profile_name = config_dic['CAhandler']['cert_profile_name']

            if 'polling_timeout' in config_dic['CAhandler']:
                try:
                    self.polling_timeout = int(config_dic['CAhandler']['polling_timeout'])
                except Exception as err:
                    self.logger.error('CAhandler._config_server_load(): failed to load polling_timeout option: %s', err)
                    self.polling_timeout = 0

    def _config_passphrase_load(self, config_dic: Dict[str, str]):
        """ load passphrase """
        self.logger.debug('CAhandler._config_passphrase_load()')
        if 'cert_passphrase_variable' in config_dic['CAhandler'] or 'cert_passphrase' in config_dic['CAhandler']:
            if 'cert_passphrase_variable' in config_dic['CAhandler']:
                self.logger.debug('CAhandler._config_passphrase_load(): load passphrase from environment variable')
                try:
                    self.cert_passphrase = os.environ[config_dic['CAhandler']['cert_passphrase_variable']]
                except Exception as err:
                    self.logger.error('CAhandler._config_passphrase_load() could not load cert_passphrase_variable:%s', err)

            if 'cert_passphrase' in config_dic['CAhandler']:
                self.logger.debug('CAhandler._config_passphrase_load(): load passphrase from config file')
                if self.cert_passphrase:
                    self.logger.info('CAhandler._config_load() overwrite cert_passphrase')
                self.cert_passphrase = config_dic['CAhandler']['cert_passphrase']
        self.logger.debug('CAhandler._config_passphrase_load() ended')

    def _config_session_load(self, config_dic: Dict[str, str]):
        """ load session """
        self.logger.debug('CAhandler._config_session_load()')

        with requests.Session() as self.session:
            # client auth via pem files
            if 'client_cert' in config_dic['CAhandler'] and 'client_key' in config_dic['CAhandler']:
                self.logger.debug('CAhandler._config_session_load() cert and key in pem format')
                self.session.cert = (config_dic['CAhandler']['client_cert'], config_dic['CAhandler']['client_key'])

            else:
                self._config_passphrase_load(config_dic)
                if 'client_cert' in config_dic['CAhandler'] and self.cert_passphrase:
                    self.session.mount(self.host, Pkcs12Adapter(pkcs12_filename=config_dic['CAhandler']['client_cert'], pkcs12_password=self.cert_passphrase))
                else:
                    self.logger.error('CAhandler._config_load() configuration incomplete: either "client_cert. "client_key" or "client_passphrase[_variable] parameter is missing in config file')
        self.logger.debug('CAhandler._config_session_load() ended')

    def _config_load(self):
        """" load config from file """
        self.logger.debug('CAhandler._config_load()')

        config_dic = load_config(self.logger, 'CAhandler')

        # load configuration
        self._config_server_load(config_dic)
        self._config_ca_load(config_dic)
        self._config_session_load(config_dic)
        # load allowed domainlist
        self.allowed_domainlist = config_allowed_domainlist_load(self.logger, config_dic)

        if 'CAhandler' in config_dic and 'client_cert' in config_dic['CAhandler'] and not self.ca_bundle:
            self.logger.error('CAhandler._config_load() configuration wrong: client authentication requires a ca_bundle.')

        # check configuration for completeness
        variable_dic = self.__dict__
        for ele in ['host', 'cert_profile_name', 'endpoint_name']:
            if not variable_dic[ele]:
                self.logger.error('CAhandler._config_load(): configuration incomplete: parameter "%s" is missing in configuration file.', ele)
        self.logger.debug('CAhandler._config_load() ended')

    def _enroll(self, data_dic: Dict[str, str]) -> Tuple[str, str, str, str]:
        """ enroll operation  """
        self.logger.debug('CAhandler._enroll()')

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None
        poll_cnt = math.ceil(self.polling_timeout / 10) + 1
        break_loop = False

        cnt = 1
        while cnt <= poll_cnt:
            cnt += 1
            sign_response = self._rpc_post(self.rpc_path + self.endpoint_name, data_dic)
            if 'result' in sign_response and 'state' in sign_response['result'] and sign_response['result']['state'].upper() == 'SUCCESS':
                # successful enrollment
                (error, cert_bundle, cert_raw) = self._cert_bundle_create(sign_response['result'])
                poll_indentifier = sign_response['result']['data']['cert_identifier']
                break_loop = True
            elif 'result' in sign_response and 'state' in sign_response['result'] and sign_response['result']['state'].upper() == 'PENDING':
                # request to be approved by operator
                poll_indentifier = sign_response['result']['data']['transaction_id']
                self.logger.info('CAhandler.enroll(): Request pending. Transaction_id: %s Workflow_id: %s', poll_indentifier, sign_response['result']['id'])
            else:
                # ernoll failed
                error = 'Malformed response'
                self.logger.error('CAhandler.enroll(): Malformed Rest response: %s', sign_response)
                break_loop = True

            if break_loop:
                break

            if cnt < poll_cnt:
                # sleep
                time.sleep(10)

        self.logger.debug('CAhandler._enroll() ended: Poll_identifier: %s', poll_indentifier)
        return (error, cert_bundle, cert_raw, poll_indentifier)

    def _rpc_post(self, path: str, data_dic: Dict[str, str]) -> Dict[str, str]:
        """ enrollment via post request to openxpki RPC interface """
        self.logger.debug('CAhandler._rpc_post()')
        try:
            # enroll via rpc
            response = self.session.post(self.host + path, json=data_dic, verify=self.ca_bundle, proxies=self.proxy, timeout=self.request_timeout).json()

        except Exception as err_:
            self.logger.error('CAhandler._rpc_post() returned an error: %s', err_)
            response = {}

        self.logger.debug('CAhandler._rpc_post() ended.')
        return response

    def _revoke(self, cert_identifier: str, rev_reason: str) -> Tuple[int, str, str]:
        """ exceute revokation via rpc call """
        self.logger.debug('CAhandler._revoke()')
        code = None
        message = None
        detail = None

        if self.host:

            data_dic = {'method': 'RevokeCertificate', 'cert_identifier': cert_identifier, 'reason_code': rev_reason}
            revocation_response = self._rpc_post(self.rpc_path + self.endpoint_name, data_dic)

            if 'result' in revocation_response and 'state' in revocation_response['result'] and revocation_response['result']['state'].upper() == 'SUCCESS':
                code = 200
            else:
                code = 400
                message = self.err_msg_dic['serverinternal']
                detail = 'Revocation failed'
                self.logger.error('CAhandler._revoke() failed with: %s', revocation_response)

        else:
            code = 400
            message = self.err_msg_dic['serverinternal']
            detail = 'Incomplete configuration'

        self.logger.debug('CAhandler._revoke() ended with: %s %s', code, detail)
        return (code, message, detail)

    def enroll(self, csr: str) -> Tuple[str, str, str, str]:
        """ enroll certificate  """
        self.logger.debug('CAhandler.enroll()')

        cert_bundle = None
        error = None
        cert_raw = None
        poll_indentifier = None

        if self.host:

            # check for allowed domainlist
            error = allowed_domainlist_check(self.logger, csr, self.allowed_domainlist)

            if not error:
                # prepare the CSR to be signed
                csr = build_pem_file(self.logger, None, b64_url_recode(self.logger, csr), None, True)

                data_dic = {
                    'method': 'RequestCertificate',
                    'comment': 'acme2certifier',
                    'pkcs10': csr,
                    'cert_profile': self.cert_profile_name
                }
                if self.session:
                    # enroll via RPC
                    (error, cert_bundle, cert_raw, poll_indentifier) = self._enroll(data_dic)
                else:
                    self.logger.error('CAhandler.enroll(): Configuration incomplete. Clientauthentication is missing...')
                    error = 'Configuration incomplete'
        else:
            self.logger.error('CAhandler.enroll(): Configuration incomplete. Host variable is missing...')
            error = 'Configuration incomplete'

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

    def revoke(self, cert: str, rev_reason: str = 'unspecified', rev_date: str = None) -> Tuple[int, str, str]:
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke(%s: %s)', rev_reason, rev_date)
        code = None
        message = None
        detail = None

        # get certifcate identifier based on common name search
        # cert_cn = cert_cn_get(self.logger, cert)
        # cert_identifier = self._cert_identifier_get(cert_cn)
        cert_raw = b64_url_recode(self.logger, cert)
        cert_identifier = self._cert_identifier_get(cert_raw)

        if cert_identifier:
            (code, message, detail) = self._revoke(cert_identifier, rev_reason)
        else:
            code = 400
            message = self.err_msg_dic['serverinternal']
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
