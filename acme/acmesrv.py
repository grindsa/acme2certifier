#!/usr/bin/python
# -*- coding: utf-8 -*-
""" cgi based acme server for Netguard Certificate manager / Insta certifier """
from __future__ import print_function
import uuid
import base64
import json
from datetime import datetime
from acme.cgi_handler import DBstore
# from acme.django_handler import DBstore

def print_debug(debug, text):
    """ little helper to print debug messages
        args:
            debug = debug flag
            text  = text to print
        returns:
            (text)
    """
    if debug:
        print('{0}: {1}'.format(datetime.now(), text))

class ACMEsrv(object):
    """ ACME server class """

    server_name = None

    def __init__(self, debug=None, srv_name=None):
        self.server_name = srv_name
        self.debug = debug
        self.dbstore = DBstore(self.debug)

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def account_new(self, content):
        """ generate a new account """
        try:
            content = json.loads(content)
        except ValueError:
            content = None

        if content and 'protected' in content and 'payload' in content and 'signature' in content:
            protected_decoded = self.decode_deserialize(content['protected'])
            payload_decoded = self.decode_deserialize(content['payload'])
            if 'nonce' in protected_decoded:
                (code, message, detail) = self.nonce_check_and_delete(protected_decoded['nonce'])
            else:
                code = 400
                message = 'urn:ietf:params:acme:error:badNonce'
                detail = 'NONE'
        else:
            code = 400
            message = 'content Json decoding error'
            detail = None

        if code != 200 and detail:
            detail = '{0} {1}'.format(self.acme_errormessage(message), detail)

        return(code, message, detail)

    @staticmethod
    def acme_errormessage(message):
        """ dictionary containing the implemented acme error messages """
        error_dic = {
            'urn:ietf:params:acme:error:badNonce' : 'JWS has invalid anti-replay nonce',
        }
        if message:
            return error_dic[message]
        else:
            return None

    def directory_get(self):
        """ return response to ACME directory call """
        print_debug(self.debug, 'ACMEsrv.directory_get()')
        d_dic = {
            'newNonce': self.server_name + '/acme/newnonce',
            'newAccount': self.server_name + '/acme/newaccount',

            'key-change': self.server_name + '/acme/key-change',
            'new-authz': self.server_name + '/acme/new-authz',
            'meta' : {
                'home': 'https://github.com/grindsa/acme2certifier',
                'author': 'grindsa <grindelsack@gmail.com>',
            },
            'new-cert': self.server_name + '/acme/new-cert',

            'revoke-cert': self.server_name + '/acme/revoke-cert'
        }
        # generate random key in json as recommended by LE
        d_dic[uuid.uuid4().hex] = 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417'
        return d_dic

    def  nonce_check_and_delete(self, nonce):
        """ check if nonce exists and delete it """
        print_debug(self.debug, 'ACMEsrv.nonce_check_and_delete({0})'.format(nonce))
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

    def nonce_generate_and_add(self):
        """ generate new nonce and store it """
        print_debug(self.debug, 'ACMEsrv.nonce_generate_and_add()')
        nonce = self.nonce_new()
        print_debug(self.debug, 'got nonce: {0}'.format(nonce))
        _id = self.dbstore.nonce_add(nonce)
        return nonce

    def servername_get(self):
        """ dumb function to return servername """
        print_debug(self.debug, 'ACMEsrv.servername_get()')
        return self.server_name

    def nonce_new(self):
        """ generate a new nonce """
        print_debug(self.debug, 'ACMEsrv.nonce_new()')
        return uuid.uuid4().hex

    @staticmethod
    def b64decode_pad(string):
        """ b64 decoding and padding of missing "=" """
        string += '=' * (-len(string) % 4)  # restore stripped '='s
        try:
            b64dec = base64.b64decode(string)
        except TypeError:
            b64dec = 'ERR: b64 decoding error'
        return b64dec

    def decode_deserialize(self, string):
        """ decode and deserialize string """
        # b64 decode
        string_decode = self.b64decode_pad(string)
        # deserialize if b64 decoding was successful
        if string_decode and string_decode != 'ERR: b64 decoding error':
            try:
                string_decode = json.loads(string_decode)
            except ValueError:
                string_decode = 'ERR: Json decoding error'

        return string_decode
