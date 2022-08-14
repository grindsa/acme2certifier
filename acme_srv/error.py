#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Error class """
# pylint: disable=c0209
from __future__ import print_function


class Error(object):
    """ error messages """

    def __init__(self, debug=None, logger=None):
        self.debug = debug
        self.logger = logger

    def _acme_errormessage(self, message):
        """ dictionary containing the implemented acme error messages """
        self.logger.debug('Error.acme_errormessage({0})'.format(message))
        error_dic = {
            'urn:ietf:params:acme:error:accountDoesNotExist': None,
            'urn:ietf:params:acme:error:badCSR': None,
            'urn:ietf:params:acme:error:badNonce': 'JWS has invalid anti-replay nonce',
            'urn:ietf:params:acme:error:invalidContact': 'The provided contact URI was invalid',
            'urn:ietf:params:acme:error:malformed': None,
            'urn:ietf:params:acme:error:serverInternal': None,
            'urn:ietf:params:acme:error:unauthorized': None,
            'urn:ietf:params:acme:error:userActionRequired': None,
            'urn:ietf:params:acme:error:alreadyRevoked': None,
            'notImplementedYet': "we are not that far. Stay tuned",
        }
        if message and message in error_dic:
            result = error_dic[message]
        else:
            result = None
        return result

    def enrich_error(self, message, detail=None):
        """ put some more content into the error messgae """
        self.logger.debug('Error.enrich_error()')
        error_message = self._acme_errormessage(message)

        if message and error_message:
            detail = '{0}: {1}'.format(error_message, detail)
        elif error_message:
            detail = '{0}{1}'.format(error_message, detail)

        return detail
