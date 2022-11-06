#!/usr/bin/python
# -*- coding: utf-8 -*-
# pylint: disable=c0209
""" message class """
from __future__ import print_function
import json
from acme_srv.helper import decode_message, load_config
from acme_srv.error import Error
from acme_srv.db_handler import DBstore
from acme_srv.nonce import Nonce
from acme_srv.signature import Signature


class Message(object):
    """ Message  handler """

    def __init__(self, debug=None, srv_name=None, logger=None):
        self.debug = debug
        self.logger = logger
        self.nonce = Nonce(self.debug, self.logger)
        self.dbstore = DBstore(self.debug, self.logger)
        self.server_name = srv_name
        self.path_dic = {'acct_path': '/acme/acct/', 'revocation_path': '/acme/revokecert'}
        self.disable_dic = {'signature_check_disable': False, 'nonce_check_disable': False}
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

        if 'Directory' in config_dic and 'url_prefix' in config_dic['Directory']:
            self.path_dic = {k: config_dic['Directory']['url_prefix'] + v for k, v in self.path_dic.items()}

    def _name_rev_get(self, content):
        """ this is needed for cases where we get a revocation message signed with account key but account name is missing """
        self.logger.debug('Message._name_rev_get()')

        try:
            account_list = self.dbstore.account_lookup('jwk', json.dumps(content['jwk']))
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Message._name_rev_get(): {0}'.format(err_))
            account_list = []
        if account_list:
            if 'name' in account_list:
                kid = account_list['name']
            else:
                kid = None
        else:
            kid = None

        self.logger.debug('Message._name_rev_get() ended with kid: {0}'.format(kid))
        return kid

    def _name_get(self, content):
        """ get name for account """
        self.logger.debug('Message._name_get()')

        if 'kid' in content:
            self.logger.debug('kid: {0}'.format(content['kid']))
            kid = content['kid'].replace('{0}{1}'.format(self.server_name, self.path_dic['acct_path']), '')
            if '/' in kid:
                kid = None
        elif 'jwk' in content and 'url' in content:
            if content['url'] == '{0}{1}'.format(self.server_name, self.path_dic['revocation_path']):
                # this is needed for cases where we get a revocation message signed with account key but account name is missing
                kid = self._name_rev_get(content)
            else:
                kid = None
        else:
            kid = None
        self.logger.debug('Message._name_get() returns: {0}'.format(kid))
        return kid

    def _check(self, skip_nonce_check, skip_signature_check, content, protected, use_emb_key):
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

        self.logger.debug('Message._check() ended with: {0}'.format(code))
        return (code, message, detail, account_name)

    # pylint: disable=R0914
    def check(self, content, use_emb_key=False, skip_nonce_check=False):
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

        self.logger.debug('Message.check() ended with:{0}'.format(code))
        return (code, message, detail, protected, payload, account_name)

    def cli_check(self, content):
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

        self.logger.debug('Message.check() ended with:{0}'.format(code))
        return (code, message, detail, protected, payload, account_name, permissions)

    def prepare_response(self, response_dic, status_dic, add_nonce=True):
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
        else:
            # add nonce to header
            if add_nonce:
                response_dic['header']['Replay-Nonce'] = self.nonce.generate_and_add()

        return response_dic
