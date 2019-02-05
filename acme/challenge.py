#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Signature class """
from __future__ import print_function
import json
from acme.helper import generate_random_string, parse_url, print_debug, load_config, jwk_thumbprint_get, url_get
from acme.db_handler import DBstore
from acme.message import Message

class Challenge(object):
    """ Challenge handler """

    def __init__(self, debug=None, srv_name=None, expiry=3600):
        self.debug = debug
        self.server_name = srv_name
        self.dbstore = DBstore(self.debug)
        self.message = Message(self.debug, self.server_name)
        self.path_dic = {'chall_path' : '/acme/chall/', 'authz_path' : '/acme/authz/'}
        self.expiry = expiry
        self.challenge_validation_disable = False

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self.load_config()
        return self

    def __exit__(self, *args):
        """ close the connection at the end of the context """

    def get(self, url):
        """ get challenge details based on get request """
        print_debug(self.debug, 'challenge.new_get({0})'.format(url))
        challenge_name = self.name_get(url)
        response_dic = {}
        response_dic['code'] = 200
        response_dic['data'] = self.info(challenge_name)
        return response_dic

    def info(self, challenge_name):
        """ get challenge details """
        print_debug(self.debug, 'Challenge.info({0})'.format(challenge_name))
        challenge_dic = self.dbstore.challenge_lookup('name', challenge_name)
        return challenge_dic

    def name_get(self, url):
        """ get challenge """
        print_debug(self.debug, 'Challenge.get_name({0})'.format(url))
        url_dic = parse_url(self.debug, url)
        challenge_name = url_dic['path'].replace(self.path_dic['chall_path'], '')
        if '/' in challenge_name:
            (challenge_name, _sinin) = challenge_name.split('/', 1)
        return challenge_name

    def new(self, authz_name, mtype, token):
        """ new challenge """
        print_debug(self.debug, 'Challenge.new({0})'.format(mtype))

        challenge_name = generate_random_string(self.debug, 12)

        data_dic = {
            'name' : challenge_name,
            'expires' : self.expiry,
            'type' : mtype,
            'token' : token,
            'authorization' : authz_name,
            'status': 2
        }
        chid = self.dbstore.challenge_add(data_dic)

        challenge_dic = {}
        if chid:
            challenge_dic['type'] = mtype
            challenge_dic['url'] = '{0}{1}{2}'.format(self.server_name, self.path_dic['chall_path'], challenge_name)
            challenge_dic['token'] = token

        return challenge_dic

    def new_set(self, authz_name, token):
        """ net challenge set """
        print_debug(self.debug, 'Challenge.new_set({0}, {1})'.format(authz_name, token))
        challenge_list = []
        challenge_list.append(self.new(authz_name, 'http-01', token))
        challenge_list.append(self.new(authz_name, 'dns-01', token))
        print_debug(self.debug, 'Challenge.new_set returned ({0})'.format(challenge_list))
        return challenge_list

    def parse(self, content):
        """ new oder request """
        print_debug(self.debug, 'Challenge.parse()')

        response_dic = {}
        # check message
        (code, message, detail, protected, payload, _account_name) = self.message.check(content)
        if code == 200:
            if 'url' in protected:
                challenge_name = self.name_get(protected['url'])
                if challenge_name:
                    challenge_dic = self.info(challenge_name)
                    # update challenge state to 'processing' - i am not so sure about this
                    # self.update({'name' : challenge_name, 'status' : 4})
                    # start validation
                    _validation = self.validate(challenge_name, payload)
                    if challenge_dic:
                        response_dic['data'] = {}
                        challenge_dic['url'] = protected['url']
                        code = 200
                        response_dic['data'] = {}
                        response_dic['data'] = challenge_dic
                        response_dic['header'] = {}
                        response_dic['header']['Link'] = '<{0}{1}>;rel="up"'.format(self.server_name, self.path_dic['authz_path'])
                    else:
                        code = 400
                        message = 'urn:ietf:params:acme:error:malformed'
                        detail = 'invalid challenge: {0}'.format(challenge_name)
                else:
                    code = 400
                    message = 'urn:ietf:params:acme:error:malformed'
                    detail = 'could not get challenge'
            else:
                code = 400
                message = 'urn:ietf:params:acme:error:malformed'
                detail = 'url missing in protected header'
        # prepare/enrich response
        status_dic = {'code': code, 'message' : message, 'detail' : detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)
        print_debug(self.debug, 'challenge.parse() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic

    def update(self, data_dic):
        """ update challenge """
        print_debug(self.debug, 'Challenge.update({0})'.format(data_dic))
        self.dbstore.challenge_update(data_dic)

    def update_authz(self, challenge_name):
        """ update authorizsation based on challenge_name """
        print_debug(self.debug, 'Challenge.update_authz({0})'.format(challenge_name))

        # lookup autorization based on challenge_name
        authz_name = self.dbstore.challenge_lookup('name', challenge_name, ['authorization__name'])['authorization']
        self.dbstore.authorization_update({'name' : authz_name, 'status' : 'valid'})
        # print(authz_name)

    def validate(self, challenge_name, payload):
        """ validate challenge"""
        print_debug(self.debug, 'Challenge.validate({0}: {1})'.format(challenge_name, payload))

        if self.challenge_validation_disable:
            print_debug(self.debug, 'CHALLENGE VALIDATION DISABLED. SETTING challenge status to valid')
            challenge_check = True
        else:
            challenge_check = self.check(challenge_name, payload)

        if challenge_check:
            self.update({'name' : challenge_name, 'status' : 'valid'})

        if 'keyAuthorization' in payload:
            # update challenge to ready state
            data_dic = {'name' : challenge_name, 'keyauthorization' : payload['keyAuthorization']}
            # self.update(data_dic)

            # authorization update to ready state
            # self.update_authz(challenge_name)
        print_debug(self.debug, 'Challenge.validate() ended')

    def load_config(self):
        """" load config from file """
        print_debug(self.debug, 'Challenge.load_config()')
        config_dic = load_config()
        if 'Challenge' in config_dic:
            self.challenge_validation_disable = config_dic.getboolean('Challenge', 'challenge_validation_disable')
        print_debug(self.debug, 'Challenge.load_config() ended.')

    def validate_http_challenge(self, fqdn, token, challenge):
        """ validate http challenge """
        print_debug(self.debug, 'Challenge.validate_http_challenge()')
        req = url_get(self.debug, 'http://{0}/.well-known/acme-challenge/{1}'.format(fqdn, token))
        if req == '{0}.{1}'.format(token, challenge):
            result = True
        else:
            result = False
        print_debug(self.debug, 'Challenge.validate_http_challenge() ended with: {0}'.format(result))
        return result

    def check(self, challenge_name, payload):
        """ challene check """
        print_debug(self.debug, 'challenge.check({0})'.format(challenge_name))
        challenge_dic = self.dbstore.challenge_lookup('name', challenge_name, ['type', 'status__name', 'token', 'authorization__name', 'authorization__type', 'authorization__value', 'authorization__token', 'authorization__order__account__name'])

        if 'type' in challenge_dic and 'authorization__value' in challenge_dic and 'token' in challenge_dic and 'authorization__order__account__name' in challenge_dic:
            pub_key = self.dbstore.jwk_load(challenge_dic['authorization__order__account__name'])
            if  pub_key:
                jwk_thumbprint = jwk_thumbprint_get(self.debug, pub_key)
                if challenge_dic['type'] == 'http-01' and jwk_thumbprint:
                    result = self.validate_http_challenge(challenge_dic['authorization__value'], challenge_dic['token'], jwk_thumbprint)
                else:
                    result = False
            else:
                result = False
        else:
            result = False
        print_debug(self.debug, 'challenge.check() ended with: {0}'.format(result))
