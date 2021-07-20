#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Nonce class """
from __future__ import print_function
import uuid
from acme_srv.db_handler import DBstore

class Acmechallenge(object):
    """ Acmechallenge handler """

    def __init__(self, debug=None, srv_name=None, logger=None):
        self.server_name = srv_name
        self.debug = debug
        self.logger = logger
        self.dbstore = DBstore(self.debug, self.logger)

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _new(self):
        """ generate a new nonce """
        self.logger.debug('Nonce.nonce__new()')
        return uuid.uuid4().hex

    def lookup(self, path_info):
        """ check nonce """
        self.logger.debug('Acmechallenge.lookup()')

        if path_info:
            token = path_info.replace('/.well-known/acme-challenge/', '')
            challenge_dic = self.dbstore.cahandler_lookup('name', token)

            if challenge_dic and 'value1' in challenge_dic:
                key_authorization = challenge_dic[ 'value1']
            else:
                key_authorization = None
                
        self.logger.debug('Acmechallenge.lookup() ended with: {0}'.format(key_authorization))
        return key_authorization
