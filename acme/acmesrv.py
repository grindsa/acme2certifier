#!/usr/bin/python
""" cgi based acme server for Netguard Certificate manager / Insta certifier """
from __future__ import print_function
import random
import string
import uuid

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
        char_set = string.ascii_uppercase + string.digits
        d_dic[''.join(random.sample(char_set*6, 6))] = 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417'
        return d_dic

    def get_server_name(self):
        """ dumb function to return servername """
        return self.server_name
        
    def newnonce(self):
        """ generate a new nonce """
        return(uuid.uuid4().hex)
