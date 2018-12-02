#!/usr/bin/python
""" cgi based acme server for Netguard Certificate manager / Insta certifier """
from __future__ import print_function
import uuid
import base64
import json
from pprint import pprint

class ACMEsrv(object):
    """ ACME server class """

    server_name = None

    def __init__(self, srv_name=None):
        self.server_name = srv_name
        # self.nonce = nonce

    def __enter__(self):
        """
        Makes ACMEHandler a Context Manager

        """
        return self

    def __exit__(self, *args):
        """
        Close the connection at the end of the context
        """

    def get_directory(self):
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

    def get_server_name(self):
        """ dumb function to return servername """
        return self.server_name

    def newaccount(self, content):
        """ generate a new nonce """
        try:
            content = json.loads(content)
        except ValueError:
            content = None

        if content and 'protected' in content and 'payload' in content and 'signature' in content:
            protected_decoded = self.decode_deserialize(content['protected'])
            payload_decoded = self.decode_deserialize(content['payload'])
        else:
            result = 'ERR: content Json decoding error'

        return(result)

    def newnonce(self):
        """ generate a new nonce """
        return uuid.uuid4().hex

    def b64decode_pad(self, string):
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
