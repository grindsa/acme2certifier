#!/usr/bin/python
""" cgi based acme server for Netguard Certificate manager / Insta certifier """
from __future__ import print_function
import os
import json
import random
import string

class ACMEHandler(object):
    """ ACME server class """

    server_name = None

    def __init__(self):
        self.get_server_name()

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
            'key-change': self.server_name + '/acme/key-change',
            'new-authz': self.server_name + '/acme/new-authz',
            'meta' : {
                'home': 'https://github.com/grindsa/acme2certifier',
                'author': 'grindsa <grindelsack@gmail.com>',
            },
            'new-cert': self.server_name + '/acme/new-cert',
            'new-reg': self.server_name + '/acme/new-reg',
            'revoke-cert': self.server_name + '/acme/revoke-cert'
        }
        char_set = string.ascii_uppercase + string.digits
        d_dic[''.join(random.sample(char_set*6, 6))] = 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417'
        return json.dumps(d_dic)

    def get_http_header(self):
        """ return full http header """
        return os.environ

    def get_server_name(self):
        """ dumb function to return servername """
        try:
            self.server_name = os.environ['SERVER_NAME']
            return self.server_name
        except KeyError:
            return json.dumps({'error': 'SERVER_NAME variable missing...'})

    def get_uri(self):
        """ returns url """
        try:
            return os.environ['REQUEST_URI']
        except KeyError:
            return json.dumps({'error': 'REQUEST_URI variable missing...'})

    def return_error(self):
        """ returns an error message """
        return json.dumps({'error': 'dont now what to do'})

if __name__ == "__main__":

    with ACMEHandler() as acm:

        # print("Content-type: text/html")
        print("Content-Type: application/json")
        print()
        URI = acm.get_uri()

        if URI == '/directory':
            print(acm.get_directory())
        else:
            print(acm.return_error())
