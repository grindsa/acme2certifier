# -*- coding: utf-8 -*-
# pylint: disable=r0913
""" message class """
from __future__ import print_function
import json
from typing import Tuple, Dict
from acme_srv.helper import decode_message, load_config, eab_handler_load, uts_to_date_utc, uts_now
from acme_srv.error import Error
from acme_srv.db_handler import DBstore
from acme_srv.nonce import Nonce
from acme_srv.signature import Signature


class Message(object):
    """ Message  handler """

    def __init__(self, debug: bool = False, srv_name: str = None, logger: object = None):
        self.debug = debug
        self.logger = logger
        self.nonce = Nonce(self.debug, self.logger)
        self.dbstore = DBstore(self.debug, self.logger)
        self.server_name = srv_name
        self.path_dic = {'acct_path': '/acme/acct/', 'revocation_path': '/acme/revokecert'}
        self.disable_dic = {'signature_check_disable': False, 'nonce_check_disable': False}
        self.eabkid_check_disable = False
        self.invalid_eabkid_deactivate = False
        self.eab_handler = None
        self._config_load()

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _config_load(self):
        """" load config from file """
        self.logger.debug('_config_load()')
        config_dic = load_config()
        if 'Nonce' in config_dic:
            self.disable_dic['nonce_check_disable'] = config_dic.getboolean('Nonce', 'nonce_check_disable', fallback=False)
            self.disable_dic['signature_check_disable'] = config_dic.getboolean('Nonce', 'signature_check_disable', fallback=False)

        if 'EABhandler' in config_dic:
            if config_dic.getboolean('EABhandler', 'eabkid_check_disable', fallback=False):
                # disable eabkid check no need to lead handler
                self.eabkid_check_disable = True
            elif 'eab_handler_file' in config_dic['EABhandler']:
                # load eab_handler according to configuration as we need to check kid
                eab_handler_module = eab_handler_load(self.logger, config_dic)
                if eab_handler_module:
                    self.invalid_eabkid_deactivate = config_dic.getboolean('EABhandler', 'invalid_eabkid_deactivate', fallback=False)
                    # store handler in variable
                    self.eab_handler = eab_handler_module.EABhandler
                else:
                    self.logger.critical('Message._config_load(): EABHandler could not get loaded')
            else:
                self.logger.critical('Message._config_load(): EABHandler configuration incomplete')
        else:
            # no eab_handler configuration found - disable check
            self.eabkid_check_disable = True

        if 'Directory' in config_dic and 'url_prefix' in config_dic['Directory']:
            self.path_dic = {k: config_dic['Directory']['url_prefix'] + v for k, v in self.path_dic.items()}

    def _invalid_eab_check(self, account_name: str):
        """ check for accounts with invalid eab credentials """
        self.logger.debug('Message._invalid_eab_check()')

        account_dic = self.dbstore.account_lookup('name', account_name, vlist=['id', 'eab_kid', 'status_id'])
        if account_dic:
            eab_kid = account_dic.get('eab_kid', None)
            if eab_kid:
                with self.eab_handler(self.logger) as eab_handler:
                    eab_mac_key = eab_handler.mac_key_get(eab_kid)
                    if not eab_mac_key:
                        self.logger.error('EAB credentials: %s could not be found in eab-credential store.', eab_kid)
                        if self.invalid_eabkid_deactivate:
                            # deactivate account
                            self.logger.error('Account %s will be deactivated due to missing eab credentials', account_name)
                            data_dic = {'name': account_name, 'status_id': 7, 'jwk': f'DEACTIVATED invalid_eabkid_deactivate {uts_to_date_utc(uts_now())}'}
                            _result = self.dbstore.account_update(data_dic, active=False)
                        # invalidate account_name
                        account_name = None
            else:
                # no eab credentials found
                self.logger.error('Account %s has no eab credentials', account_name)
                account_name = None
        else:
            self.logger.error('Account lookup for  %s failed.', account_name)
            account_name = None

        self.logger.debug('Message._invalid_eab_check() ended with account_name: %s', account_name)
        return account_name

    def _name_rev_get(self, content: Dict[str, str]) -> str:
        """ this is needed for cases where we get a revocation message signed with account key but account name is missing """
        self.logger.debug('Message._name_rev_get()')

        try:
            account_list = self.dbstore.account_lookup('jwk', json.dumps(content['jwk']))
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Message._name_rev_get(): %s', err_)
            account_list = []
        if account_list:
            if 'name' in account_list:
                kid = account_list['name']
            else:
                kid = None
        else:
            kid = None

        self.logger.debug('Message._name_rev_get() ended with kid: %s', kid)
        return kid

    def _name_get(self, content: Dict[str, str]) -> str:
        """ get name for account """
        self.logger.debug('Message._name_get()')

        if 'kid' in content:
            self.logger.debug('kid: %s', content['kid'])
            kid = content['kid'].replace(f'{self.server_name}{self.path_dic["acct_path"]}', '')
            if '/' in kid:
                kid = None
        elif 'jwk' in content and 'url' in content:
            if content['url'] == f'{self.server_name}{self.path_dic["revocation_path"]}':
                # this is needed for cases where we get a revocation message signed with account key but account name is missing
                kid = self._name_rev_get(content)
            else:
                kid = None
        else:
            kid = None
        self.logger.debug('Message._name_get() returns: %s', kid)
        return kid

    def _check(self, skip_nonce_check: bool, skip_signature_check: bool, content: str, protected: Dict[str, str], use_emb_key: bool) -> Tuple[int, str, str, str]:
        """ decoding successful - check nonce for anti replay protection """
        self.logger.debug('Message._check()')

        account_name = None
        if skip_nonce_check or self.disable_dic['nonce_check_disable']:
            # nonce check can be skipped by configuration and in case of key-rollover
            if self.disable_dic['nonce_check_disable']:
                self.logger.error('**** NONCE CHECK DISABLED!!! Severe security issue ****')
            else:
                self.logger.info('skip nonce check of inner payload during keyrollover')
            code = 200
            message = None
            detail = None
        else:
            (code, message, detail) = self.nonce.check(protected)

        self.logger.debug('Message._nonce_check() ended with: %s', code)
        return (code, message, detail)

    def _check(self, skip_nonce_check: bool, skip_signature_check: bool, content: str, protected: Dict[str, str], use_emb_key: bool) -> Tuple[int, str, str, str]:
        """ decoding successful - check nonce for anti replay protection """
        self.logger.debug('Message._check()')

        (code, message, detail) = self._nonce_check(skip_nonce_check, protected)
        account_name = None

        # nonce check successful - get account name
        account_name = self._name_get(protected)
        # check for invalid eab-credentials if not disabled and not using embedded key
        if code == 200 and not self.eabkid_check_disable and not use_emb_key:
            account_name = self._invalid_eab_check(account_name)
            if not account_name:
                return (403, 'urn:ietf:params:acme:error:unauthorized', 'invalid eab credentials', None)

        if code == 200 and not skip_signature_check:
            # nonce check successful - check signature
            account_name = self._name_get(protected)
            signature = Signature(self.debug, self.server_name, self.logger)
            # we need the decoded protected header to grab a key to verify signature
            (sig_check, error, error_detail) = signature.check(account_name, content, use_emb_key, protected)
            if sig_check:
                code = 200
                message = None
                detail = None
            else:
                code = 403
                message = error
                detail = error_detail

        self.logger.debug('Message._check() ended with: %s', code)
        return (code, message, detail, account_name)

    # pylint: disable=R0914
    def check(self, content: str, use_emb_key: bool = False, skip_nonce_check: bool = False) -> Tuple[int, str, str, Dict[str, str], Dict[str, str], str]:
        """ validate message """
        self.logger.debug('Message.check()')

        # disable signature check if paramter has been set
        if self.disable_dic['signature_check_disable']:
            self.logger.error('**** SIGNATURE_CHECK_DISABLE!!! Severe security issue ****')
            skip_signature_check = True
        else:
            skip_signature_check = False

        # decode message
        (result, error_detail, protected, payload, _signature) = decode_message(self.logger, content)
        account_name = None
        if result:
            (code, message, detail, account_name) = self._check(skip_nonce_check, skip_signature_check, content, protected, use_emb_key)
        else:
            # message could not get decoded
            code = 400
            message = 'urn:ietf:params:acme:error:malformed'
            detail = error_detail

        self.logger.debug('Message.check() ended with:%s', code)
        return (code, message, detail, protected, payload, account_name)

    def cli_check(self, content: str) -> Tuple[int, str, str, Dict[str, str], Dict[str, str], str, Dict[str, str]]:
        """ validate message coming from CLI client """
        self.logger.debug('Message.cli_check()')

        # decode message
        (result, error_detail, protected, payload, _signature) = decode_message(self.logger, content)
        account_name = None
        permissions = {}
        if result:
            # check signature
            account_name = self._name_get(protected)
            signature = Signature(self.debug, self.server_name, self.logger)
            # we need the decoded protected header to grab a key to verify signature
            (sig_check, error, error_detail) = signature.cli_check(account_name, content)
            if sig_check:
                code = 200
                message = None
                detail = None
                permissions = self.dbstore.cli_permissions_get(account_name)
            else:
                code = 403
                message = error
                detail = error_detail
        else:
            # message could not get decoded
            code = 400
            message = 'urn:ietf:params:acme:error:malformed'
            detail = error_detail

        self.logger.debug('Message.check() ended with:%s', code)
        return (code, message, detail, protected, payload, account_name, permissions)

    def prepare_response(self, response_dic: Dict[str, str], status_dic: Dict[str, str], add_nonce: bool = True) -> Dict[str, str]:
        """ prepare response_dic """
        self.logger.debug('Message.prepare_response()')
        if 'code' not in status_dic:
            status_dic['code'] = 400
            status_dic['type'] = 'urn:ietf:params:acme:error:serverInternal'
            status_dic['detail'] = 'http status code missing'

        if 'type' not in status_dic:
            status_dic['type'] = 'urn:ietf:params:acme:error:serverInternal'

        if 'detail' not in status_dic:
            status_dic['detail'] = None

        # create response
        response_dic['code'] = status_dic['code']

        # create header if not existing
        if 'header' not in response_dic:
            response_dic['header'] = {}

        if status_dic['code'] >= 400:
            if status_dic['detail']:
                # some error occured get details
                error_message = Error(self.debug, self.logger)
                status_dic['detail'] = error_message.enrich_error(status_dic['type'], status_dic['detail'])
                response_dic['data'] = {'status': status_dic['code'], 'type': status_dic['type'], 'detail': status_dic['detail']}
            else:
                response_dic['data'] = {'status': status_dic['code'], 'type': status_dic['type']}

        # always add nonce to header
        if add_nonce:
            response_dic['header']['Replay-Nonce'] = self.nonce.generate_and_add()

        return response_dic
