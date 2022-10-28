#!/usr/bin/python
# -*- coding: utf-8 -*-
# pylint: disable=E0401, R1705, C0209
""" wsgi based acme server """
from __future__ import print_function
import re
import json
import sys
from wsgiref.simple_server import make_server, WSGIRequestHandler
from acme_srv.account import Account
from acme_srv.acmechallenge import Acmechallenge
from acme_srv.authorization import Authorization
from acme_srv.certificate import Certificate
from acme_srv.challenge import Challenge
from acme_srv.directory import Directory
from acme_srv.housekeeping import Housekeeping
from acme_srv.nonce import Nonce
from acme_srv.order import Order
from acme_srv.trigger import Trigger
from acme_srv.helper import get_url, load_config, logger_setup, logger_info, config_check
from acme_srv.version import __dbversion__, __version__

# load config to set debug mode
CONFIG = load_config()
try:
    DEBUG = CONFIG.getboolean('DEFAULT', 'debug')
except Exception:
    DEBUG = False


def handle_exception(exc_type, exc_value, exc_traceback):
    """ exception handler """
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    # LOGGER.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    LOGGER.error("Uncaught exception")


# initialize logger
LOGGER = logger_setup(DEBUG)

with Housekeeping(DEBUG, LOGGER) as db_check:
    db_check.dbversion_check(__dbversion__)

# examption handling via logger
sys.excepthook = handle_exception

HTTP_CODE_DIC = {
    200: 'Created',
    201: 'OK',
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    500: 'serverInternal '
}

ERR_STRING = json.dumps({'status': 405, 'message': HTTP_CODE_DIC[405], 'detail': 'Wrong request type. Expected POST.'}).encode('utf-8')
WSG_INPUT_VARNAME = 'wsgi.input'
CONTENT_TYPE = ('Content-Type', 'application/json')
METHOD_NOT_ALLOWED_RESPONSE = '405 {0}'.format(HTTP_CODE_DIC[405]), [CONTENT_TYPE]


def create_header(response_dic, add_json_header=True):
    """ create header """
    # generate header and nonce
    if add_json_header:
        if 'code' in response_dic:
            if response_dic['code'] in (200, 201):
                headers = [CONTENT_TYPE]
            else:
                headers = [('Content-Type', 'application/problem+json')]
        else:
            headers = [CONTENT_TYPE]
    else:
        headers = []

    # enrich header
    if 'header' in response_dic:
        for element, value in response_dic['header'].items():
            headers.append((element, value))

    return headers


def get_request_body(environ):
    """ get body from request data """
    try:
        request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    except ValueError:
        request_body_size = 0
    if WSG_INPUT_VARNAME in environ:
        request_body = environ[WSG_INPUT_VARNAME].read(request_body_size)
    else:
        request_body = None
    return request_body


def acct(environ, start_response):
    """ account handling """
    with Account(DEBUG, get_url(environ), LOGGER) as account:
        request_body = get_request_body(environ)
        response_dic = account.parse(request_body)

        # create header
        headers = create_header(response_dic)
        start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)
        return [json.dumps(response_dic['data']).encode('utf-8')]


def acmechallenge_serve(environ, start_response):
    """ directory listing """
    with Acmechallenge(DEBUG, get_url(environ), LOGGER) as acmechallenge:
        key_authorization = acmechallenge.lookup(environ['PATH_INFO'])
        if not key_authorization:
            key_authorization = 'NOT FOUND'
            start_response('404 {0}'.format(HTTP_CODE_DIC[404]), [('Content-Type', 'text/html')])
        else:
            start_response('200 {0}'.format(HTTP_CODE_DIC[200]), [('Content-Type', 'text/html')])
        # logging
        logger_info(LOGGER, environ['REMOTE_ADDR'], environ['PATH_INFO'], {})
        return [key_authorization.encode('utf-8')]


def authz(environ, start_response):
    """ authorization handling """
    if 'REQUEST_METHOD' in environ and environ['REQUEST_METHOD'] in ('POST', 'GET'):
        with Authorization(DEBUG, get_url(environ), LOGGER) as authorization:
            if environ['REQUEST_METHOD'] == 'POST':
                try:
                    request_body_size = int(environ.get('CONTENT_LENGTH', 0))
                except ValueError:
                    request_body_size = 0
                request_body = environ[WSG_INPUT_VARNAME].read(request_body_size)
                response_dic = authorization.new_post(request_body)
            else:
                response_dic = authorization.new_get(get_url(environ, True))

            # create header
            headers = create_header(response_dic)
            start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)

            # logging
            logger_info(LOGGER, environ['REMOTE_ADDR'], environ['PATH_INFO'], response_dic)
            return [json.dumps(response_dic['data']).encode('utf-8')]
    else:
        start_response(METHOD_NOT_ALLOWED_RESPONSE)
        return [ERR_STRING]


def newaccount(environ, start_response):
    """ create new account """
    if environ['REQUEST_METHOD'] == 'POST':

        with Account(DEBUG, get_url(environ), LOGGER) as account:
            request_body = get_request_body(environ)
            response_dic = account.new(request_body)

            # create header
            headers = create_header(response_dic)
            start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)

            # logging
            logger_info(LOGGER, environ['REMOTE_ADDR'], environ['PATH_INFO'], response_dic)
            return [json.dumps(response_dic['data']).encode('utf-8')]

    else:
        start_response(METHOD_NOT_ALLOWED_RESPONSE)
        return [ERR_STRING]


def directory(environ, start_response):
    """ directory listing """
    with Directory(DEBUG, get_url(environ), LOGGER) as direct_tory:
        headers = create_header({'code': 200})
        start_response('200 OK', headers)
        # logging
        logger_info(LOGGER, environ['REMOTE_ADDR'], environ['PATH_INFO'], '')
        return [json.dumps(direct_tory.directory_get()).encode('utf-8')]


def cert(environ, start_response):
    """ create new account """
    with Certificate(DEBUG, get_url(environ), LOGGER) as certificate:
        if environ['REQUEST_METHOD'] == 'POST':
            request_body = get_request_body(environ)
            response_dic = certificate.new_post(request_body)
            # create header
            headers = create_header(response_dic, False)
            start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)

            # logging
            logger_info(LOGGER, environ['REMOTE_ADDR'], environ['PATH_INFO'], response_dic)
            return [response_dic['data'].encode('utf-8')]

        elif environ['REQUEST_METHOD'] == 'GET':

            response_dic = certificate.new_get(get_url(environ, True))
            # create header
            headers = create_header(response_dic)
            # create the response
            start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)

            # logging
            logger_info(LOGGER, environ['REMOTE_ADDR'], environ['PATH_INFO'], response_dic)
            # send response
            return [response_dic['data']]

        else:
            start_response(METHOD_NOT_ALLOWED_RESPONSE)
            return [ERR_STRING]


def chall(environ, start_response):
    """ create new account """
    with Challenge(DEBUG, get_url(environ), LOGGER) as challenge:
        if environ['REQUEST_METHOD'] == 'POST':

            request_body = get_request_body(environ)
            response_dic = challenge.parse(request_body)

            # create header
            headers = create_header(response_dic)
            start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)

            # logging
            logger_info(LOGGER, environ['REMOTE_ADDR'], environ['PATH_INFO'], response_dic)
            return [json.dumps(response_dic['data']).encode('utf-8')]

        elif environ['REQUEST_METHOD'] == 'GET':

            response_dic = challenge.get(get_url(environ, True))

            # generate header
            headers = [CONTENT_TYPE]
            # create the response
            start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)

            # logging
            logger_info(LOGGER, environ['REMOTE_ADDR'], environ['PATH_INFO'], response_dic)
            # send response
            return [json.dumps(response_dic['data']).encode('utf-8')]

        else:
            start_response(METHOD_NOT_ALLOWED_RESPONSE)
            return [ERR_STRING]


def newnonce(environ, start_response):
    """ generate a new nonce """
    if environ['REQUEST_METHOD'] in ['HEAD', 'GET']:
        nonce = Nonce(DEBUG, LOGGER)
        headers = [('Content-Type', 'text/plain'), ('Replay-Nonce', '{0}'.format(nonce.generate_and_add()))]
        status = '200 OK' if environ['REQUEST_METHOD'] == 'HEAD' else '204 No content'
        start_response(status, headers)
        return []
    else:
        start_response(METHOD_NOT_ALLOWED_RESPONSE)
        return [json.dumps({'status': 405, 'message': HTTP_CODE_DIC[405], 'detail': 'Wrong request type. Expected HEAD or GET.'}).encode('utf-8')]


def neworders(environ, start_response):
    """ generate a new order """
    if environ['REQUEST_METHOD'] == 'POST':
        with Order(DEBUG, get_url(environ), LOGGER) as norder:
            request_body = get_request_body(environ)
            response_dic = norder.new(request_body)

            # create header
            headers = create_header(response_dic)
            start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)

            # logging
            logger_info(LOGGER, environ['REMOTE_ADDR'], environ['PATH_INFO'], response_dic)
            return [json.dumps(response_dic['data']).encode('utf-8')]

    else:
        start_response(METHOD_NOT_ALLOWED_RESPONSE)
        return [ERR_STRING]


def order(environ, start_response):
    """ order_handler """
    if environ['REQUEST_METHOD'] == 'POST':
        with Order(DEBUG, get_url(environ), LOGGER) as eorder:
            request_body = get_request_body(environ)
            response_dic = eorder.parse(request_body)

            # create header
            headers = create_header(response_dic)
            start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)

            # logging
            logger_info(LOGGER, environ['REMOTE_ADDR'], environ['PATH_INFO'], response_dic)
            return [json.dumps(response_dic['data']).encode('utf-8')]

    else:
        start_response(METHOD_NOT_ALLOWED_RESPONSE)
        return [ERR_STRING]


def revokecert(environ, start_response):
    """ revocation_handler """
    if environ['REQUEST_METHOD'] == 'POST':
        with Certificate(DEBUG, get_url(environ), LOGGER) as certificate:
            request_body = get_request_body(environ)
            response_dic = certificate.revoke(request_body)

            # create header
            headers = create_header(response_dic)
            start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)

            # logging
            logger_info(LOGGER, environ['REMOTE_ADDR'], environ['PATH_INFO'], response_dic)
            if 'data' in response_dic:
                return [json.dumps(response_dic['data']).encode('utf-8')]
            else:
                return []
    else:
        start_response(METHOD_NOT_ALLOWED_RESPONSE)
        return [ERR_STRING]


def trigger(environ, start_response):
    """ ca trigger handler """
    if environ['REQUEST_METHOD'] == 'POST':
        with Trigger(DEBUG, get_url(environ), LOGGER) as trigger_:
            request_body = get_request_body(environ)
            response_dic = trigger_.parse(request_body)

            # create header
            headers = create_header(response_dic)
            start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)

            # logging
            logger_info(LOGGER, environ['REMOTE_ADDR'], environ['PATH_INFO'], response_dic)

            if 'data' in response_dic:
                return [json.dumps(response_dic['data']).encode('utf-8')]
            else:
                return []
    else:
        start_response(METHOD_NOT_ALLOWED_RESPONSE)
        return [ERR_STRING]


def housekeeping(environ, start_response):
    """ cli housekeeping handler """
    if environ['REQUEST_METHOD'] == 'POST':
        with Housekeeping(DEBUG, LOGGER) as housekeeping_:
            request_body = get_request_body(environ)
            response_dic = housekeeping_.parse(request_body)

            # create header
            headers = create_header(response_dic)
            start_response('{0} {1}'.format(response_dic['code'], HTTP_CODE_DIC[response_dic['code']]), headers)

            # logging
            logger_info(LOGGER, environ['REMOTE_ADDR'], environ['PATH_INFO'], '****')

            if 'data' in response_dic:
                return [json.dumps(response_dic['data']).encode('utf-8')]
            else:
                return []
    else:
        start_response(METHOD_NOT_ALLOWED_RESPONSE)
        return [ERR_STRING]


def not_found(_environ, start_response):
    ''' called if no URL matches '''
    start_response('404 NOT FOUND', [('Content-Type', 'text/plain')])
    return [json.dumps({'status': 404, 'message': HTTP_CODE_DIC[404], 'detail': 'Not Found'}).encode('utf-8')]


# map urls to functions
URLS = [
    (r'^$', directory),
    (r'^acme/acct', acct),
    (r'^acme/authz', authz),
    (r'^acme/cert', cert),
    (r'^acme/chall', chall),
    (r'^acme/key-change', acct),
    (r'^acme/newaccount$', newaccount),
    (r'^acme/newnonce$', newnonce),
    (r'^acme/neworders$', neworders),
    (r'^acme/order', order),
    (r'^acme/revokecert', revokecert),
    (r'^directory?$', directory),
    (r'^housekeeping', housekeeping),
    (r'^trigger', trigger)]


def application(environ, start_response):
    ''' The main WSGI application if nothing matches call the not_found function.'''

    # check if we need to activate the url pattern for challenge verification
    if 'CAhandler' in CONFIG and 'acme_url' in CONFIG['CAhandler']:
        URLS.append((r'^.well-known/acme-challenge/', acmechallenge_serve))

    prefix = '/'
    if 'Directory' in CONFIG and 'url_prefix' in CONFIG['Directory']:
        prefix = CONFIG['Directory']['url_prefix'] + '/'
    path = environ.get('PATH_INFO', '').lstrip(prefix)

    for regex, callback in URLS:
        match = re.search(regex, path)
        if match is not None:
            environ['myapp.url_args'] = match.groups()
            return callback(environ, start_response)
    return not_found(environ, start_response)


def get_handler_cls():
    """ my handler to disable name resolution """
    cls = WSGIRequestHandler

    # disable dns resolution in BaseHTTPServer.py
    class Acme2certiferhandler(cls, object):
        """ source: https://review.opendev.org/#/c/79876/9/ceilometer/api/app.py """
        def address_string(self):
            return self.client_address[0]

    return Acme2certiferhandler


if __name__ == '__main__':

    LOGGER.info('starting acme2certifier version %s', __version__)

    # check configuration for parameters masked in ""
    config_check(LOGGER, CONFIG)

    SRV = make_server('0.0.0.0', 80, application, handler_class=get_handler_cls())
    SRV.serve_forever()
