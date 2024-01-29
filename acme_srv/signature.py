# -*- coding: utf-8 -*-
""" Signature class """
from __future__ import print_function
from typing import Tuple, Dict
from acme_srv.helper import signature_check, load_config, error_dic_get
from acme_srv.db_handler import DBstore


class Signature(object):
    """ Signature handler """

    def __init__(self, debug: bool = False, srv_name: str = None, logger: object = None):
        self.debug = debug
        self.logger = logger
        self.dbstore = DBstore(self.debug, self.logger)
        self.err_msg_dic = error_dic_get(self.logger)
        self.server_name = srv_name
        cfg = load_config()
        if 'Directory' in cfg:
            if 'url_prefix' in cfg['Directory']:
                self.revocation_path = cfg['Directory']['url_prefix'] + '/acme/revokecert'
            else:
                self.revocation_path = '/acme/revokecert'

    def _cli_jwk_load(self, kid: int) -> Dict[str, str]:
        """ get key for a specific account id """
        self.logger.debug('Signature._cli_jwk_load(%s)', kid)
        try:
            result = self.dbstore.cli_jwk_load(kid)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Signature._cli_jwk_load(): %s', err_)
            result = None
        return result

    def _jwk_load(self, kid: str) -> Dict[str, str]:
        """ get key for a specific account id """
        self.logger.debug('Signature._jwk_load(%s)', kid)
        try:
            result = self.dbstore.jwk_load(kid)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Signature._jwk_load(): %s', err_)
            result = None
        return result

    def cli_check(self, aname: str, content: str) -> Tuple[str, str, None]:
        """ signature check against cli key """
        self.logger.debug('Signature.cli_check(%s)', aname)
        result = False
        error = None

        if content:
            if aname:
                self.logger.debug('check signature against account key')
                pub_key = self._cli_jwk_load(aname)
                if pub_key:
                    (result, error) = signature_check(self.logger, content, pub_key)
                else:
                    error = self.err_msg_dic['accountdoesnotexist']
            else:
                error = self.err_msg_dic['accountdoesnotexist']
        else:
            error = self.err_msg_dic['malformed']

        self.logger.debug('Signature.cli_check() ended with: %s:%s', result, error)
        return (result, error, None)

    def check(self, aname: str, content: str, use_emb_key: bool = False, protected: Dict[str, str] = None) -> Tuple[str, str, None]:
        """ signature check """
        self.logger.debug('Signature.check(%s)', aname)
        result = False
        if content:
            error = None
            if aname:
                self.logger.debug('check signature against account key')
                pub_key = self._jwk_load(aname)
                if pub_key:
                    (result, error) = signature_check(self.logger, content, pub_key)
                else:
                    error = self.err_msg_dic['accountdoesnotexist']
            elif use_emb_key:
                self.logger.debug('check signature against key includedn in jwk')
                if 'jwk' in protected:
                    pub_key = protected['jwk']
                    (result, error) = signature_check(self.logger, content, pub_key)
                else:
                    error = self.err_msg_dic['accountdoesnotexist']
            else:
                error = self.err_msg_dic['accountdoesnotexist']
        else:
            error = self.err_msg_dic['malformed']

        self.logger.debug('Signature.check() ended with: %s:%s', result, error)
        return (result, error, None)

    def eab_check(self, content: str, mac_key: str) -> Tuple[str, str]:
        """ signature check """
        self.logger.debug('Signature.eab_check()')
        result = False
        error = None
        if content and mac_key:
            (result, error) = signature_check(self.logger, content, mac_key, json_=True)

        self.logger.debug('Signature.signature_check() ended with: %s:%s', result, error)
        return (result, error)
