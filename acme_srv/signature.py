#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Signature class """
from __future__ import print_function
from acme_srv.helper import signature_check, load_config
from acme_srv.db_handler import DBstore

class Signature(object):
    """ Signature handler """

    def __init__(self, debug=None, srv_name=None, logger=None):
        self.debug = debug
        self.logger = logger
        self.dbstore = DBstore(self.debug, self.logger)
        self.server_name = srv_name
        cfg = load_config()
        if 'Directory' in cfg:            
            if 'url_prefix' in cfg['Directory']:
                self.revocation_path = cfg['Directory']['url_prefix'] + '/acme_srv/revokecert' 
            else:
                self.revocation_path = '/acme_srv/revokecert' 
        

    def _jwk_load(self, kid):
        """ get key for a specific account id """
        self.logger.debug('Signature._jwk_load({0})'.format(kid))
        try:
            result = self.dbstore.jwk_load(kid)
        except BaseException as err_:
            print(err_)
            self.logger.critical('acme2certifier database error in Signature._hwk_load(): {0}'.format(err_))
            result = None
        return result

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
                    error = 'urn:ietf:params:acme:error:accountDoesNotExist'
            elif use_emb_key:
                self.logger.debug('check signature against key includedn in jwk')
                if 'jwk' in protected:
                    pub_key = protected['jwk']
                    (result, error) = signature_check(self.logger, content, pub_key)
                else:
                    error = 'urn:ietf:params:acme:error:accountDoesNotExist'
            else:
                error = 'urn:ietf:params:acme:error:accountDoesNotExist'
        else:
            error = 'urn:ietf:params:acme:error:malformed'

        self.logger.debug('Signature.check() ended with: {0}:{1}'.format(result, error))
        return(result, error, None)

    def eab_check(self, content, mac_key):
        """ signature check """
        self.logger.debug('Signature.eab_check()')
        result = False
        error = None
        if content and mac_key:
            (result, error) = signature_check(self.logger, content, mac_key, json_=True)

        return(result, error)
