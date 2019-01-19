#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Order class """
from __future__ import print_function
import json
from acme.db_handler import DBstore
from acme.challenge import Challenge
from acme.helper import generate_random_string, print_debug, uts_now, uts_to_date_utc
from acme.message import Message
from acme.nonce import Nonce

class Authorization(object):
    """ class for order handling """

    def __init__(self, debug=None, srv_name=None, expiry=86400):
        self.server_name = srv_name
        self.debug = debug
        self.dbstore = DBstore(self.debug)
        self.message = Message(self.debug, self.server_name)
        self.nonce = Nonce(self.debug)
        self.expiry = expiry
        self.authz_path = '/acme/authz/'
        # self.order_path = '/acme/order/'

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def authz_info(self, url):
        """ return authzs information """
        print_debug(self.debug, 'Authorization.info({0})'.format(url))
        authz_name = url.replace('{0}{1}'.format(self.server_name, self.authz_path), '')

        expires = uts_now() + self.expiry
        token = generate_random_string(self.debug, 22)
        # update authorization with expiry date and token (just to be sure)
        self.dbstore.authorization_update({'name' : authz_name, 'token' : token, 'expires' : expires})

        authz_info_dic = {}
        authz_info_dic['expires'] = uts_to_date_utc(expires)

        # get authorization information from db to be inserted in message
        auth_info = self.dbstore.authorization_lookup('name', authz_name, ['status__name', 'type', 'value'])
        if auth_info:
            authz_info_dic['status'] = auth_info[0]['status__name']
            authz_info_dic['identifier'] = {'type' : auth_info[0]['type'], 'value' : auth_info[0]['value']}
        challenge = Challenge(self.debug, self.server_name, expires)
        authz_info_dic['challenges'] = challenge.new_set(authz_name, token)

        print_debug(self.debug, 'Authorization.authz_info() returns: {0}'.format(json.dumps(authz_info_dic)))
        return authz_info_dic

    def new_get(self, url):
        """ challenge computation based on get request """
        print_debug(self.debug, 'Authorization.new_get()')
        response_dic = {}
        response_dic['code'] = 200
        response_dic['header'] = {}
        response_dic['data'] = self.authz_info(url)
        return response_dic

    def new_post(self, content):
        """ challenge computation based on post request """
        print_debug(self.debug, 'Authorization.new_post()')

        response_dic = {}
        # check message
        (code, message, detail, protected, _payload, _account_name) = self.message.check(content)
        if code == 200:
            if 'url' in protected:
                response_dic['data'] = self.authz_info(protected['url'])
            else:
                code = 400
                message = 'urn:ietf:params:acme:error:malformed'
                detail = 'url is missing in protected'

        # prepare/enrich response
        status_dic = {'code': code, 'message' : message, 'detail' : detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        print_debug(self.debug, 'Authorization.new_post() returns: {0}'.format(json.dumps(response_dic)))

        return response_dic
