#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Error class """
from __future__ import print_function
from acme.helper import print_debug

class Error(object):
    """ error messages """

    def __init__(self, debug=None):
        self.debug = debug

    def enrich_error(self, message, detail):
        """ put some more content into the error messgae """
        print_debug(self.debug, 'Account.enrich_error()')
        if message and self.acme_errormessage(message):
            detail = '{0} {1}'.format(self.acme_errormessage(message), detail)
        else:
            detail = '{0}{1}'.format(self.acme_errormessage(message), detail)

        return detail

    def acme_errormessage(self, message):
        """ dictionary containing the implemented acme error messages """
        print_debug(self.debug, 'Error.acme_errormessage({0})'.format(message))
        error_dic = {
            'urn:ietf:params:acme:error:accountDoesNotExist' : '',
            'urn:ietf:params:acme:error:badCSR' : '',
            'urn:ietf:params:acme:error:badNonce' : 'JWS has invalid anti-replay nonce',
            'urn:ietf:params:acme:error:invalidContact' : 'The provided contact URI was invalid',
            'urn:ietf:params:acme:error:malformed' : '',
            'urn:ietf:params:acme:error:serverInternal' : '',
            'urn:ietf:params:acme:error:unauthorized' : '',
            'urn:ietf:params:acme:error:userActionRequired' : '',
            'notImplementedYet' : "we are not that far. Stay tuned",
        }
        if message:
            return error_dic[message]
        else:
            return None
