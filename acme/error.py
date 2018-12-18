#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Error class """
from __future__ import print_function
from acme.helper import print_debug

class Error(object):
    """ error messages """

    def __init__(self, debug=None):
        self.debug = debug

    def acme_errormessage(self, message):
        """ dictionary containing the implemented acme error messages """
        print_debug(self.debug, 'Error.acme_errormessage({0})'.format(message))
        error_dic = {
            'urn:ietf:params:acme:error:badNonce' : 'JWS has invalid anti-replay nonce',
            'urn:ietf:params:acme:error:invalidContact' : 'The provided contact URI was invalid',
            'urn:ietf:params:acme:error:userActionRequired' : '',
            'urn:ietf:params:acme:error:malformed' : '',
            'urn:ietf:params:acme:error:accountDoesNotExist' : "",
        }
        if message:
            return error_dic[message]
        else:
            return None
