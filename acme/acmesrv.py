#!/usr/bin/python
# -*- coding: utf-8 -*-
""" cgi based acme server for Netguard Certificate manager / Insta certifier """
from __future__ import print_function
import uuid
import base64
import json
from acme.cgi_handler import DBstore
# from acme.django_handler import DBstore

class ACMEsrv(object):
    """ ACME server class """

    server_name = None

    def __init__(self, srv_name=None):
        self.server_name = srv_name
        self.dbstore = DBstore()

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
                detail = 'JWS has no anti-replay nonce'
        else:
            code = 400
            message = 'content Json decoding error'
            detail = None

        return(code, message, detail)

    def directory_get(self):
        """ return response to ACME directory call """
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
        # generate random key in json has as recommended by LE
        d_dic[uuid.uuid4().hex] = 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417'
        return d_dic

    def  nonce_check_and_delete(self, nonce):
        """ check if nonce exists and delete it """
        if self.dbstore.nonce_check(nonce):
            self.dbstore.nonce_delete(nonce)
            code = 200
            message = None
            detail = None
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:badNonce'
            detail = 'JWS has invalid anti-replay nonce {0}'.format(nonce)
        return(code, message, detail)

    def nonce_generate_and_add(self):
        """ generate new nonce and store it """
        nonce = self.nonce_new()
        _id = self.dbstore.nonce_add(nonce)
        return nonce

    def servername_get(self):
        """ dumb function to return servername """
        return self.server_name

    @staticmethod
    def nonce_new():
        """ generate a new nonce """
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
