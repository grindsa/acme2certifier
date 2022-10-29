#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Signature class """
# pylint: disable=c0209
from __future__ import print_function
from acme_srv.helper import signature_check, load_config, error_dic_get
from acme_srv.db_handler import DBstore


class Signature(object):
    """ Signature handler """

    def __init__(self, debug=None, srv_name=None, logger=None):
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

    def _cli_jwk_load(self, kid):
        """ get key for a specific account id """
        self.logger.debug('Signature._cli_jwk_load({0})'.format(kid))
        try:
            result = self.dbstore.cli_jwk_load(kid)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Signature._cli_jwk_load(): {0}'.format(err_))
            result = None
        return result

    def _jwk_load(self, kid):
        """ get key for a specific account id """
        self.logger.debug('Signature._jwk_load({0})'.format(kid))
        try:
            result = self.dbstore.jwk_load(kid)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Signature._jwk_load(): {0}'.format(err_))
            result = None
        return result

    def cli_check(self, aname, content):
        """ signature check against cli key """
        self.logger.debug('Signature.cli_check({0})'.format(aname))
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

        self.logger.debug('Signature.cli_check() ended with: {0}:{1}'.format(result, error))
        return (result, error, None)

    def check(self, aname, content, use_emb_key=False, protected=None):
        """ signature check """
        self.logger.debug('Signature.check({0})'.format(aname))
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

        self.logger.debug('Signature.check() ended with: {0}:{1}'.format(result, error))
        return (result, error, None)

    def eab_check(self, content, mac_key):
        """ signature check """
        self.logger.debug('Signature.eab_check()')
        result = False
        error = None
        if content and mac_key:
            (result, error) = signature_check(self.logger, content, mac_key, json_=True)

        return (result, error)
