#!/usr/bin/python
# -*- coding: utf-8 -*-
""" wsgi based acme server """
from __future__ import print_function
import re
from cgi import escape
import json
import os
from acme.account import Account
from acme.directory import Directory
from acme.nonce import Nonce
from acme.helper import print_debug, get_url

DEBUG = True

HTTP_CODE_DIC = {
    200 : 'Created',
    201 : 'OK',
    400 : 'Bad Request',
    401 : 'Unauthorized',
    403 : 'Forbidden',
    404 : 'Not Found',
    405 : 'Method Not Allowed'
}

def acct(environ, start_response):
    """ account handling """
    account = Account(DEBUG, get_url(environ))
    nonce = Nonce(DEBUG)

    try:
        request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    except ValueError:
        request_body_size = 0
    request_body = environ['wsgi.input'].read(request_body_size)
    response_dic = account.parse(request_body)

    # generate header and nonce
    headers = [('Content-Type', 'application/json'), ('Replay-Nonce', '{0}'.format(nonce.generate_and_add()))]

    # enrich header
    for element, value in response_dic['header'].items():
        print_debug(DEBUG,'newaccount header {0}: {1}'.format(element, value))
        headers.append((element, value))
    start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)
    return [json.dumps(response_dic['data'])]

def directory(environ, start_response):
    """ directory listing """
    direct_tory = Directory(DEBUG, get_url(environ))
    start_response('200 OK', [('Content-Type', 'application/json')])
    return [json.dumps(direct_tory.directory_get())]

def newaccount(environ, start_response):
    """ create new account """
    if environ['REQUEST_METHOD'] == 'POST':
        account = Account(DEBUG, get_url(environ))
        nonce = Nonce(DEBUG)

        try:
            request_body_size = int(environ.get('CONTENT_LENGTH', 0))
        except ValueError:
            request_body_size = 0
        request_body = environ['wsgi.input'].read(request_body_size)
        response_dic = account.new(request_body)

        # generate header and nonce
        headers = [('Content-Type', 'application/json'), ('Replay-Nonce', '{0}'.format(nonce.generate_and_add()))]
        # enrich header
        for element, value in response_dic['header'].items():
            print_debug(DEBUG,'newaccount header {0}: {1}'.format(element, value))
            headers.append((element, value))
        start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)
        return [json.dumps(response_dic['data'])]

    else:
        start_response('405 {0}'.format(HTTP_CODE_DIC[405]), [('Content-Type', 'application/json')])
        return [json.dumps({'status':405, 'message':HTTP_CODE_DIC[405], 'detail': 'Wrong request type. Expected POST.'})]

def newnonce(environ, start_response):
    """ generate a new nonce """
    if environ['REQUEST_METHOD'] == 'HEAD':
        nonce = Nonce(DEBUG)
        headers = [('Content-Type', 'text/plain'), ('Replay-Nonce', '{0}'.format(nonce.generate_and_add()))]
        start_response('200 OK', headers)
        return []
    else:
        start_response('405 {0}'.format(HTTP_CODE_DIC[405]), [('Content-Type', 'application/json')])
        return [json.dumps({'status':405, 'message':HTTP_CODE_DIC[405], 'detail': 'Wrong request type. Expected HEAD.'})]

def not_found(_environ, start_response):
    ''' called if no URL matches '''
    start_response('404 NOT FOUND', [('Content-Type', 'text/plain')])
    return [json.dumps({'status':404, 'message':HTTP_CODE_DIC[404], 'detail': 'Not Found'})]

# map urls to functions
URLS = [
    (r'^$', directory),
    (r'^directory?$', directory),
    (r'^acme/newaccount$', newaccount),
    (r'^acme/newnonce$', newnonce),
    (r'^acme/acct', acct),
]

def application(environ, start_response):
    ''' The main WSGI application if nothing matches call the not_found function.'''
    path = environ.get('PATH_INFO', '').lstrip('/')
    for regex, callback in URLS:
        match = re.search(regex, path)
        if match is not None:
            environ['myapp.url_args'] = match.groups()
            return callback(environ, start_response)
    return not_found(environ, start_response)

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    SRV = make_server('0.0.0.0', 80, application)
    SRV.serve_forever()
