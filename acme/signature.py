#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Signature class """
from __future__ import print_function
from acme.helper import print_debug, signature_check
from acme.db_handler import DBstore

class Signature(object):
    """ Signature handler """

    def __init__(self, debug=None):
        self.debug = debug
        self.dbstore = DBstore(self.debug)

    def check(self, content, aid):
        """ signature check """
        print_debug(self.debug, 'Signature.check({0})'.format(aid))

        result = False
        error = None
        if aid:
            pub_key = self.jwk_load(aid)
            if pub_key:
                (result, error) = signature_check(self.debug, content, pub_key)
            else:
                error = 'urn:ietf:params:acme:error:accountDoesNotExist'
        else:
            error = 'urn:ietf:params:acme:error:accountDoesNotExist'
        return(result, error)

    def jwk_load(self, kid):
        """ get key for a specific account id """
        print_debug(self.debug, 'Account.jwk_load({0})'.format(kid))
        return self.dbstore.jwk_load(kid)
