#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Order class """
from __future__ import print_function
import json
from acme_srv.db_handler import DBstore
from acme_srv.challenge import Challenge
from acme_srv.helper import generate_random_string, uts_now, uts_to_date_utc, load_config
from acme_srv.message import Message
from acme_srv.nonce import Nonce

class Authorization(object):
    """ class for order handling """

    def __init__(self, debug=None, srv_name=None, logger=None):
        self.server_name = srv_name
        self.debug = debug
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)
        self.message = Message(debug, self.server_name, self.logger)
        self.nonce = Nonce(debug, self.logger)
        self.validity = 86400
        self.expiry_check_disable = False
        self.path_dic = {'authz_path' : '/acme/authz/'}

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _authz_info(self, url):
        """ return authzs information """
        self.logger.debug('Authorization._authz_info({0})'.format(url))
        authz_name = url.replace('{0}{1}'.format(self.server_name, self.path_dic['authz_path']), '')
        expires = uts_now() + self.validity
        token = generate_random_string(self.logger, 32)
        authz_info_dic = {}

        # lookup authorization based on name
        try:
            authz = self.dbstore.authorization_lookup('name', authz_name)
        except BaseException as err_:
            self.logger.critical('acme2certifier database error in Authorization._authz_info(): {0}'.format(err_))
            authz = None

        if authz:
            # update authorization with expiry date and token (just to be sure)
            try:
                self.dbstore.authorization_update({'name' : authz_name, 'token' : token, 'expires' : expires})
            except BaseException as err_:
                self.logger.error('acme2certifier database error in Authorization._authz_info(): {0}'.format(err_))
            authz_info_dic['expires'] = uts_to_date_utc(expires)

            # get authorization information from db to be inserted in message
            tnauth = None
            try:
                auth_info = self.dbstore.authorization_lookup('name', authz_name, ['status__name', 'type', 'value'])
            except BaseException as err_:
                self.logger.error('acme2certifier database error in Authorization._authz_info(): {0}'.format(err_))
                auth_info = {}

            if auth_info:
                if 'status__name' in auth_info[0]:
                    authz_info_dic['status'] = auth_info[0]['status__name']
                else:
                    authz_info_dic['status'] = 'pending'

                if 'type' in auth_info[0]  and 'value' in auth_info[0]:
                    authz_info_dic['identifier'] = {'type' : auth_info[0]['type'], 'value' : auth_info[0]['value']}
                    if auth_info[0]['type'] == 'TNAuthList':
                        tnauth = True
            else:
                authz_info_dic['status'] = 'pending'

            with Challenge(self.debug, self.server_name, self.logger, expires) as challenge:
                # get challenge data (either existing or new ones)
                authz_info_dic['challenges'] = challenge.challengeset_get(authz_name, authz_info_dic['status'], token, tnauth)

        self.logger.debug('Authorization._authz_info() returns: {0}'.format(json.dumps(authz_info_dic)))
        return authz_info_dic

    def _config_load(self):
        """" load config from file """
        self.logger.debug('Authorization._config_load()')
        config_dic = load_config()
        if 'Authorization' in config_dic:
            self.expiry_check_disable = config_dic.getboolean('Authorization', 'expiry_check_disable', fallback=False)
            if 'validity' in config_dic['Authorization']:
                try:
                    self.validity = int(config_dic['Authorization']['validity'])
                except BaseException:
                    self.logger.warning('Authorization._config_load(): failed to parse validity: {0}'.format(config_dic['Authorization']['validity']))
        if 'Directory' in config_dic:
            if 'url_prefix' in config_dic['Directory']:
                self.path_dic = {k: config_dic['Directory']['url_prefix'] + v for k, v in self.path_dic.items()}
        self.logger.debug('Authorization._config_load() ended.')

    def invalidate(self, timestamp=None):
        """ invalidate authorizations """
        self.logger.debug('Authorization.invalidate({0})'.format(timestamp))
        if not timestamp:
            timestamp = uts_now()
            self.logger.debug('Authorization.invalidate(): set timestamp to {0}'.format(timestamp))

        field_list = ['id', 'name', 'expires', 'value', 'created_at', 'token', 'status__id', 'status__name', 'order__id', 'order__name']
        try:
            authz_list = self.dbstore.authorizations_expired_search('expires', timestamp, vlist=field_list, operant='<=')
        except BaseException as err_:
            self.logger.critical('acme2certifier database error in Authorization.invalidate(): {0}'.format(err_))
            authz_list = []

        output_list = []
        for authz in authz_list:
            # select all authz which are not invalid
            if 'name' in authz and 'status__name' in authz and authz['status__name'] != 'expired':
                # skip corner cases where authz expiry is set to 0
                if 'expires' not in authz or authz['expires'] > 0:
                    # change status and add to output list
                    output_list.append(authz)
                    data_dic = {'name': authz['name'], 'status': 'expired'}
                    try:
                        self.dbstore.authorization_update(data_dic)
                    except BaseException as err_:
                        self.logger.critical('acme2certifier database error in Authorization.invalidate(): {0}'.format(err_))

        self.logger.debug('Authorization.invalidate() ended: {0} authorizations identified'.format(len(output_list)))
        return (field_list, output_list)

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

        # invalidate expired authorizations
        if not self.expiry_check_disable:
            self.invalidate()

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
