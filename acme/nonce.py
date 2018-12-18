#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Nonce class """
from __future__ import print_function
import uuid
from acme.helper import print_debug
from acme.db_handler import DBstore

class Nonce(object):
    """ Nonce handler """

    def __init__(self, debug=None):
        self.debug = debug
        self.dbstore = DBstore(self.debug)

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def check(self, protected_decoded):
        """ check nonce """
        print_debug(self.debug, 'Nonce.check_nonce()')
        if 'nonce' in protected_decoded:
            (code, message, detail) = self.check_and_delete(protected_decoded['nonce'])
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:badNonce'
            detail = 'NONE'

        return(code, message, detail)

    def check_and_delete(self, nonce):
        """ check if nonce exists and delete it """
        print_debug(self.debug, 'Nonce.nonce_check_and_delete({0})'.format(nonce))
        if self.dbstore.nonce_check(nonce):
            self.dbstore.nonce_delete(nonce)
            code = 200
            message = None
            detail = None
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:badNonce'
            detail = nonce
        return(code, message, detail)

    def generate_and_add(self):
        """ generate new nonce and store it """
        print_debug(self.debug, 'Nonce.nonce_generate_and_add()')
        nonce = self.new()
        print_debug(self.debug, 'got nonce: {0}'.format(nonce))
        _id = self.dbstore.nonce_add(nonce)
        return nonce

    def new(self):
        """ generate a new nonce """
        print_debug(self.debug, 'Nonce.nonce_new()')
        return uuid.uuid4().hex
        