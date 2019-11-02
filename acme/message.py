#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca hanlder for Insta Certifier via REST-API class """
from __future__ import print_function
from acme.helper import decode_message, load_config
from acme.error import Error
from acme.db_handler import DBstore
from acme.nonce import Nonce
from acme.signature import Signature

class Message(object):
    """ Message  handler """

    def __init__(self, debug=None, srv_name=None, logger=None):
        self.debug = debug
        self.logger = logger
        self.nonce = Nonce(self.debug, self.logger)
        self.dbstore = DBstore(self.debug, self.logger)
        self.server_name = srv_name
        self.path_dic = {'acct_path' : '/acme/acct/', 'revocation_path' : '/acme/revokecert'}
        self.disable_dic = {'signature_check_disable' : False, 'nonce_check_disable' : False}
        self.load_config()

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def check(self, content, use_emb_key=False):
        """ validate message """
        self.logger.debug('Message.check()')

        # disable signature check if paramter has been set
        if self.disable_dic['signature_check_disable']:
            print('**** SIGNATURE_CHECK_DISABLE!!! Security issue ****')
            skip_signature_check = True
        else:
            skip_signature_check = False
            
        # decode message
        (result, error_detail, protected, payload, _signature) = decode_message(self.logger, content)
        account_name = None
        if result:
            # decoding successful - check nonce for anti replay protection
            (code, message, detail) = self.nonce.check(protected)
            if self.disable_dic['nonce_check_disable']:
                print('**** NONCE CHECK DISABLED!!! Security issue ****')
                code = 200
                message = None
                detail = None

            if code == 200 and not skip_signature_check:
                # nonce check successful - check signature
                account_name = self.name_get(protected)
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
        else:
            # message could not get decoded
            code = 400
            message = 'urn:ietf:params:acme:error:malformed'
            detail = error_detail

        self.logger.debug('Message.check() ended with:{0}'.format(code))
        return(code, message, detail, protected, payload, account_name)

    def load_config(self):
        """" load config from file """
        self.logger.debug('load_config()')
        config_dic = load_config()
        if 'Nonce' in config_dic:
            self.disable_dic['nonce_check_disable'] = config_dic.getboolean('Nonce', 'nonce_check_disable', fallback=False)
            self.disable_dic['signature_check_disable'] = config_dic.getboolean('Nonce', 'signature_check_disable', fallback=False)

    def name_get(self, content):
        """ get name for account """
        self.logger.debug('Message.name_get()')

        if 'kid' in content:
            self.logger.debug('kid: {0}'.format(content['kid']))
            kid = content['kid'].replace('{0}{1}'.format(self.server_name, self.path_dic['acct_path']), '')
            if '/' in kid:
                kid = None
        elif 'jwk' in content and 'url' in content:
            if content['url'] == '{0}{1}'.format(self.server_name, self.path_dic['revocation_path']):
                # this is needed for cases where we get a revocation message signed with account key but account name is missing)
                if 'n' in content['jwk']:
                    account_list = self.dbstore.account_lookup('modulus', content['jwk']['n'])
                    if account_list:
                        if 'name' in account_list:
                            kid = account_list['name']
                        else:
                            kid = None
                    else:
                        kid = None
                else:
                    kid = None
            else:
                kid = None
        else:
            kid = None
        self.logger.debug('Message.name_get() returns: {0}'.format(kid))
        return kid

    def prepare_response(self, response_dic, status_dic):
        """ prepare response_dic """
        self.logger.debug('Message.prepare_response()')
        if 'code' not in status_dic:
            status_dic['code'] = 400
            status_dic['message'] = 'urn:ietf:params:acme:error:serverInternal'
            status_dic['detail'] = 'http status code missing'

        if 'message' not in status_dic:
            status_dic['message'] = 'urn:ietf:params:acme:error:serverInternal'

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
                status_dic['detail'] = error_message.enrich_error(status_dic['message'], status_dic['detail'])
                response_dic['data'] = {'status': status_dic['code'], 'message': status_dic['message'], 'detail': status_dic['detail']}
            else:
                response_dic['data'] = {'status': status_dic['code'], 'message': status_dic['message'], 'detail': None}
        else:
            # add nonce to header
            response_dic['header']['Replay-Nonce'] = self.nonce.generate_and_add()

        return response_dic
