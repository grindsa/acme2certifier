#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Directory class """
from __future__ import print_function
import uuid
from acme.helper import print_debug

class Directory(object):
    """ class for directory handling """

    def __init__(self, debug=None, srv_name=None):
        self.server_name = srv_name
        self.debug = debug

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def directory_get(self):
        """ return response to ACME directory call """
        print_debug(self.debug, 'Directory.directory_get()')
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

    def servername_get(self):
        """ dumb function to return servername """
        print_debug(self.debug, 'Directory.servername_get()')
        return self.server_name
