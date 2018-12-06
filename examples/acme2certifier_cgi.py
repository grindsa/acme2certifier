#!/usr/bin/python
""" cgi based acme server for Netguard Certificate manager / Insta certifier """
from __future__ import print_function
import os
import json
from acme.acmesrv import ACMEsrv

def return_error(text):
    """ returns an error message """
    if text:
        return json.dumps({'error': text})
    else:
        return json.dumps({'error': 'dont now what to do'})

if __name__ == "__main__":

    DBNAME = 'acme.db'

    # obtain servername
    if 'SERVER_NAME' in os.environ:
        SERVER_NAME = os.environ['SERVER_NAME']
    else:
        SERVER_NAME = None

    # obtain path
    if 'REQUEST_URI' in os.environ:
        URI = os.environ['REQUEST_URI']
    else:
        URI = None

    # real stuff starts here
    with ACMEsrv(SERVER_NAME) as acm:

        # create database if does not exists
        if not os.path.exists(DBNAME):
            acm.store_create(DBNAME)
    
        if SERVER_NAME:
            if URI == '/acme/newnonce':
                print('Replay-Nonce: {0}'.format(acm.nonce_generate_and_add()))
                print('Content-type: text/html')
                print()
            else:
                print("Content-Type: application/json")
                print()
                if URI == '/directory' or URI == '/':
                    print(json.dumps(acm.directory_get()))

                else:
                    # print(URI)
                    print(return_error('path: {0} unknown'.format(URI)))
        else:
            print(return_error('SERVER_NAME missing'))
