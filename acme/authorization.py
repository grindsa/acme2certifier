#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Order class """
from __future__ import print_function
import json
from acme.db_handler import DBstore
from acme.challenge import Challenge
from acme.helper import generate_random_string, uts_now, uts_to_date_utc
from acme.message import Message
from acme.nonce import Nonce

class Authorization(object):
    """ class for order handling """

    def __init__(self, debug=None, srv_name=None, logger=None, expiry=86400):
        self.server_name = srv_name
        self.debug = debug
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)
        self.message = Message(debug, self.server_name, self.logger)
        self.nonce = Nonce(debug, self.logger)
        self.expiry = expiry
        self.path_dic = {'authz_path' : '/acme/authz/'}

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _authz_info(self, url):
        """ return authzs information """
        self.logger.debug('Authorization._authz_info({0})'.format(url))
        authz_name = url.replace('{0}{1}'.format(self.server_name, self.path_dic['authz_path']), '')
        expires = uts_now() + self.expiry
        token = generate_random_string(self.logger, 32)
        authz_info_dic = {}
        if self.dbstore.authorization_lookup('name', authz_name):

            # update authorization with expiry date and token (just to be sure)
            self.dbstore.authorization_update({'name' : authz_name, 'token' : token, 'expires' : expires})
            authz_info_dic['expires'] = uts_to_date_utc(expires)

            # get authorization information from db to be inserted in message
            tnauth = None
            auth_info = self.dbstore.authorization_lookup('name', authz_name, ['status__name', 'type', 'value'])
            if auth_info:
                authz_info_dic['status'] = auth_info[0]['status__name']
                authz_info_dic['identifier'] = {'type' : auth_info[0]['type'], 'value' : auth_info[0]['value']}
                if auth_info[0]['type'] == 'TNAuthList':
                    tnauth = True
            challenge = Challenge(self.debug, self.server_name, self.logger, expires)
            authz_info_dic['challenges'] = challenge.new_set(authz_name, token, tnauth)

        self.logger.debug('Authorization._authz_info() returns: {0}'.format(json.dumps(authz_info_dic)))
        return authz_info_dic

    def new_get(self, url):
        """ challenge computation based on get request """
        self.logger.debug('Authorization.new_get()')
        response_dic = {}
        response_dic['code'] = 200
        response_dic['header'] = {}
        response_dic['data'] = self._authz_info(url)
        return response_dic

    def new_post(self, content):
        """ challenge computation based on post request """
        self.logger.debug('Authorization.new_post()')

        response_dic = {}
        # check message
        (code, message, detail, protected, _payload, _account_name) = self.message.check(content)
        if code == 200:
            if 'url' in protected:
                auth_info = self._authz_info(protected['url'])
                if auth_info:
                    response_dic['data'] = auth_info
                else:
                    code = 403
                    message = 'urn:ietf:params:acme:error:unauthorized'
                    detail = 'authorizations lookup failed'
            else:
                code = 400
                message = 'urn:ietf:params:acme:error:malformed'
                detail = 'url is missing in protected'

        # prepare/enrich response
        status_dic = {'code': code, 'message' : message, 'detail' : detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug('Authorization.new_post() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic
