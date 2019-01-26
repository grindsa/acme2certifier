#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Signature class """
from __future__ import print_function
from acme.helper import print_debug, signature_check
from acme.db_handler import DBstore

class Signature(object):
    """ Signature handler """

    def __init__(self, debug=None, srv_name=None):
        self.debug = debug
        self.dbstore = DBstore(self.debug)
        self.server_name = srv_name
        self.revocation_path = '/acme/revokecert'

    def check(self, content, aname, protected=None):
        """ signature check """
        print_debug(self.debug, 'Signature.check({0})'.format(aname))

        result = False
        error = None

        if aname:
            pub_key = self.jwk_load(aname)
            if pub_key:
                (result, error) = signature_check(self.debug, content, pub_key)
            else:
                error = 'urn:ietf:params:acme:error:accountDoesNotExist'
        elif protected:     
            print_debug(self.debug, 'no account_key given'.format(aname))            
            if 'url' in protected and 'jwk' in protected:       
                # for revocation we also allow request signed with domain key
                if protected['url'] == '{0}{1}'.format(self.server_name, self.revocation_path):
                    print_debug(self.debug, 'revocation request signed with domain key')                       
                    pub_key = protected['jwk']
                    (result, error) = signature_check(self.debug, content, pub_key)
                else:
                    error = 'urn:ietf:params:acme:error:accountDoesNotExist'
            else:
                error = 'urn:ietf:params:acme:error:accountDoesNotExist'
        else:
            error = 'urn:ietf:params:acme:error:accountDoesNotExist'
        print_debug(self.debug, 'Signature.check() ended with: {0}:{1}'.format(result, error))
        return(result, error, None)

    def jwk_load(self, kid):
        """ get key for a specific account id """
        print_debug(self.debug, 'Account.jwk_load({0})'.format(kid))   
        return self.dbstore.jwk_load(kid)
