#!/usr/bin/python
""" cgi based acme server for Netguard Certificate manager / Insta certifier """
from __future__ import print_function
import os
import sys
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
    DEBUG = False

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
    with ACMEsrv(DEBUG, SERVER_NAME) as acm:

        if SERVER_NAME:
            if URI == '/acme/newaccount':
                if os.environ['REQUEST_METHOD'] == 'POST':
                    (CODE, MESSAGE, DETAIL) = acm.account_new(sys.stdin.read())
                    # generate new nonce
                    print('Replay-Nonce: {0}'.format(acm.nonce_generate_and_add()))
                    print('Content-Type: application/json')
                    print()
                    # create the response
                    print(json.dumps({'status':CODE, 'message':MESSAGE, 'detail': DETAIL}))

                    # return response
                else:
                    print('Status: 400 Bad Request')
                    print('Content-Type: application/json')
                    print()
                    print(json.dumps({'status':400, 'message':'bad request ', 'detail': 'Wrong request type. Expected POST.'}))

            elif URI == '/acme/newnonce':
                if os.environ['REQUEST_METHOD'] == 'HEAD':
                    print('Replay-Nonce: {0}'.format(acm.nonce_generate_and_add()))
                    print('Content-type: text/html')
                    print()
                else:
                    print('Status: 400 Bad Request')
                    print('Content-Type: application/json')
                    print()
                    print(json.dumps({'status':400, 'message':'bad request ', 'detail': 'Wrong request type. Expected HEAD.'}))
            else:
                print('Content-Type: application/json')
                print()
                if URI == '/directory' or URI == '/':
                    print(json.dumps(acm.directory_get()))

                else:
                    # print(URI)
                    print(return_error('path: {0} unknown'.format(URI)))
        else:
            print(return_error('SERVER_NAME missing'))
