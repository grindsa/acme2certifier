#!/usr/bin/python
# -*- coding: utf-8 -*-
""" wsgi based acme server """
from __future__ import print_function
import re
import json
from acme.account import Account
from acme.authorization import Authorization
from acme.challenge import Challenge
from acme.directory import Directory
from acme.nonce import Nonce
from acme.order import Order
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

def create_header(response_dic):
    """ create header """
    # generate header and nonce
    headers = [('Content-Type', 'application/json')]

    # enrich header
    for element, value in response_dic['header'].items():
        print_debug(DEBUG, 'acct header {0}: {1}'.format(element, value))
        headers.append((element, value))
    return headers

def get_request_body(environ):
    """ get body from request data """
    try:
        request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    except ValueError:
        request_body_size = 0
    request_body = environ['wsgi.input'].read(request_body_size)
    return request_body

def acct(environ, start_response):
    """ account handling """
    account = Account(DEBUG, get_url(environ))
    request_body = get_request_body(environ)
    response_dic = account.parse(request_body)

    # create header
    headers = create_header(response_dic)
    start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)
    return [json.dumps(response_dic['data'])]


def authz(environ, start_response):
    """ account handling """
    authorization = Authorization(DEBUG, get_url(environ))

    # try:
    #    request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    # except ValueError:
    #    request_body_size = 0
    # request_body = environ['wsgi.input'].read(request_body_size)
    # response_dic = authorization.authz_info(request_body)

    response_dic = authorization.new_get(get_url(environ, True))

    # generate header and nonce
    headers = [('Content-Type', 'application/json')]

    # enrich header
    #for element, value in response_dic['header'].items():
    #    print_debug(DEBUG, 'newaccount header {0}: {1}'.format(element, value))
    #    headers.append((element, value))
    start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)
    return [json.dumps(response_dic['data'])]

def newaccount(environ, start_response):
    """ create new account """
    if environ['REQUEST_METHOD'] == 'POST':

        account = Account(DEBUG, get_url(environ))
        request_body = get_request_body(environ)
        response_dic = account.new(request_body)

        # create header
        headers = create_header(response_dic)
        start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)
        return [json.dumps(response_dic['data'])]

    else:
        start_response('405 {0}'.format(HTTP_CODE_DIC[405]), [('Content-Type', 'application/json')])
        return [json.dumps({'status':405, 'message':HTTP_CODE_DIC[405], 'detail': 'Wrong request type. Expected POST.'})]

def directory(environ, start_response):
    """ directory listing """
    direct_tory = Directory(DEBUG, get_url(environ))
    start_response('200 OK', [('Content-Type', 'application/json')])
    return [json.dumps(direct_tory.directory_get())]

def chall(environ, start_response):
    """ create new account """
    challenge = Challenge(DEBUG, get_url(environ))
    if environ['REQUEST_METHOD'] == 'POST':

        request_body = get_request_body(environ)
        response_dic = challenge.parse(get_url(environ, True), request_body)

        # create header
        headers = create_header(response_dic)
        start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)
        return [json.dumps(response_dic['data'])]

    elif environ['REQUEST_METHOD'] == 'GET':

        response_dic = challenge.get(get_url(environ, True))

        # generate header
        headers = [('Content-Type', 'application/json')]
        # create the response
        start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)
        # send response
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


def neworders(environ, start_response):
    """ generate a new order """
    if environ['REQUEST_METHOD'] == 'POST':
        order = Order(DEBUG, get_url(environ))
        request_body = get_request_body(environ)
        response_dic = order.new(request_body)

        # create header
        headers = create_header(response_dic)
        start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)
        return [json.dumps(response_dic['data'])]

    else:
        start_response('405 {0}'.format(HTTP_CODE_DIC[405]), [('Content-Type', 'application/json')])
        return [json.dumps({'status':405, 'message':HTTP_CODE_DIC[405], 'detail': 'Wrong request type. Expected POST.'})]

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
    (r'^acme/authz', authz),
    (r'^acme/neworders$', neworders),
    (r'^acme/chall', chall),
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

# start_response('403 {0}'.format(HTTP_CODE_DIC[403]), [('Content-Type', 'application/json')])
# return [json.dumps({'status':403, 'message':HTTP_CODE_DIC[403], 'detail': 'we are not there yet'})]
