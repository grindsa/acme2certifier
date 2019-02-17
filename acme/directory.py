#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Directory class """
from __future__ import print_function
import uuid

class Directory(object):
    """ class for directory handling """

    def __init__(self, _debug=None, srv_name=None, logger=None):
        self.server_name = srv_name
        self.logger = logger

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def directory_get(self):
        """ return response to ACME directory call """
        self.logger.debug('Directory.directory_get()')
        d_dic = {
            'newNonce': self.server_name + '/acme/newnonce',
            'newAccount': self.server_name + '/acme/newaccount',
            "newOrder": self.server_name + '/acme/neworders',
            'revokeCert' : self.server_name + '/acme/revokecert',
            'keyChange' : self.server_name + '/acme/key-change',
            'meta' : {
                'home': 'https://github.com/grindsa/acme2certifier',
                'author': 'grindsa <grindelsack@gmail.com>',
            },
        }
        # generate random key in json as recommended by LE
        d_dic[uuid.uuid4().hex] = 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417'
        return d_dic

    def servername_get(self):
        """ dumb function to return servername """
        self.logger.debug('Directory.servername_get()')
        return self.server_name
