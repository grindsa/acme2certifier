#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Challenge class """
from __future__ import print_function
import json
from acme.helper import generate_random_string, parse_url, load_config, jwk_thumbprint_get, url_get, sha256_hash, b64_url_encode, txt_get
from acme.db_handler import DBstore
from acme.message import Message

class Challenge(object):
    """ Challenge handler """

    def __init__(self, debug=None, srv_name=None, logger=None, expiry=3600):
        # self.debug = debug
        self.server_name = srv_name
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)
        self.message = Message(debug, self.server_name, self.logger)
        self.path_dic = {'chall_path' : '/acme/chall/', 'authz_path' : '/acme/authz/'}
        self.expiry = expiry
        self.challenge_validation_disable = False
        self.tnauthlist_support = False

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self.load_config()
        return self

    def __exit__(self, *args):
        """ close the connection at the end of the context """

    def check(self, challenge_name, payload):
        """ challene check """
        self.logger.debug('challenge.check({0})'.format(challenge_name))
        challenge_dic = self.dbstore.challenge_lookup('name', challenge_name, ['type', 'status__name', 'token', 'authorization__name', 'authorization__type', 'authorization__value', 'authorization__token', 'authorization__order__account__name'])
        if 'type' in challenge_dic and 'authorization__value' in challenge_dic and 'token' in challenge_dic and 'authorization__order__account__name' in challenge_dic:
            pub_key = self.dbstore.jwk_load(challenge_dic['authorization__order__account__name'])
            if  pub_key:
                jwk_thumbprint = jwk_thumbprint_get(self.logger, pub_key)
                if challenge_dic['type'] == 'http-01' and jwk_thumbprint:
                    result = self.validate_http_challenge(challenge_dic['authorization__value'], challenge_dic['token'], jwk_thumbprint)
                elif challenge_dic['type'] == 'dns-01' and jwk_thumbprint:
                    result = self.validate_dns_challenge(challenge_dic['authorization__value'], challenge_dic['token'], jwk_thumbprint)
                elif challenge_dic['type'] == 'tkauth-01' and jwk_thumbprint and self.tnauthlist_support:
                    result = self.validate_tkauth_challenge(challenge_dic['authorization__value'], challenge_dic['token'], jwk_thumbprint, payload)
                else:
                    self.logger.debug('unknown challenge type "{0}". Setting check result to False'.format(challenge_dic['type']))
                    result = False
            else:
                result = False
        else:
            result = False
        self.logger.debug('challenge.check() ended with: {0}'.format(result))
        return result

    def get(self, url):
        """ get challenge details based on get request """
        self.logger.debug('challenge.new_get({0})'.format(url))
        challenge_name = self.name_get(url)
        response_dic = {}
        response_dic['code'] = 200
        response_dic['data'] = self.info(challenge_name)
        return response_dic

    def info(self, challenge_name):
        """ get challenge details """
        self.logger.debug('Challenge.info({0})'.format(challenge_name))
        challenge_dic = self.dbstore.challenge_lookup('name', challenge_name)
        return challenge_dic

    def load_config(self):
        """" load config from file """
        self.logger.debug('Challenge.load_config()')
        config_dic = load_config()
        if 'Challenge' in config_dic:
            self.challenge_validation_disable = config_dic.getboolean('Challenge', 'challenge_validation_disable', fallback=False)
        if 'Order' in config_dic:
            self.tnauthlist_support = config_dic.getboolean('Order', 'tnauthlist_support', fallback=False)
        self.logger.debug('Challenge.load_config() ended.')

    def name_get(self, url):
        """ get challenge """
        self.logger.debug('Challenge.get_name({0})'.format(url))
        url_dic = parse_url(self.logger, url)
        challenge_name = url_dic['path'].replace(self.path_dic['chall_path'], '')
        if '/' in challenge_name:
            (challenge_name, _sinin) = challenge_name.split('/', 1)
        return challenge_name

    def new(self, authz_name, mtype, token):
        """ new challenge """
        self.logger.debug('Challenge.new({0})'.format(mtype))

        challenge_name = generate_random_string(self.logger, 12)

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
            if mtype == 'tkauth-01':
                challenge_dic['tkauth-type'] = 'atc'
        return challenge_dic

    def new_set(self, authz_name, token, tnauth=False):
        """ net challenge set """
        self.logger.debug('Challenge.new_set({0}, {1})'.format(authz_name, token))
        challenge_list = []
        if not tnauth:
            challenge_list.append(self.new(authz_name, 'http-01', token))
            challenge_list.append(self.new(authz_name, 'dns-01', token))
        else:
            challenge_list.append(self.new(authz_name, 'tkauth-01', token))
        self.logger.debug('Challenge.new_set returned ({0})'.format(challenge_list))
        return challenge_list

    def parse(self, content):
        """ new oder request """
        self.logger.debug('Challenge.parse()')

        response_dic = {}
        # check message
        (code, message, detail, protected, payload, _account_name) = self.message.check(content)

        if code == 200:
            if 'url' in protected:
                challenge_name = self.name_get(protected['url'])
                if challenge_name:
                    challenge_dic = self.info(challenge_name)

                    if challenge_dic:
                        # check tnauthlist payload
                        if self.tnauthlist_support:
                            (code, message, detail) = self.validate_tnauthlist_payload(payload, challenge_dic)

                        if code == 200:
                            # update challenge state to 'processing' - i am not so sure about this
                            # self.update({'name' : challenge_name, 'status' : 4})
                            # start validation
                            _validation = self.validate(challenge_name, payload)
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
        self.logger.debug('challenge.parse() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic

    def update(self, data_dic):
        """ update challenge """
        self.logger.debug('Challenge.update({0})'.format(data_dic))
        self.dbstore.challenge_update(data_dic)

    def update_authz(self, challenge_name):
        """ update authorizsation based on challenge_name """
        self.logger.debug('Challenge.update_authz({0})'.format(challenge_name))

        # lookup autorization based on challenge_name
        authz_name = self.dbstore.challenge_lookup('name', challenge_name, ['authorization__name'])['authorization']
        self.dbstore.authorization_update({'name' : authz_name, 'status' : 'valid'})
        # print(authz_name)

    def validate(self, challenge_name, payload):
        """ validate challenge"""
        self.logger.debug('Challenge.validate({0}: {1})'.format(challenge_name, payload))
        if self.challenge_validation_disable:
            self.logger.debug('CHALLENGE VALIDATION DISABLED. SETTING challenge status to valid')
            challenge_check = True
        else:
            challenge_check = self.check(challenge_name, payload)

        if challenge_check:
            self.update({'name' : challenge_name, 'status' : 'valid'})
            # authorization update to ready state
            self.update_authz(challenge_name)

        if payload:
            if 'keyAuthorization' in payload:
                # update challenge to ready state
                data_dic = {'name' : challenge_name, 'keyauthorization' : payload['keyAuthorization']}
                self.update(data_dic)

        self.logger.debug('Challenge.validate() ended with:{0}'.format(challenge_check))

    def validate_dns_challenge(self, fqdn, token, jwk_thumbprint):
        """ validate dns challenge """
        self.logger.debug('Challenge.validate_dns_challenge()')

        # rewrite fqdn
        fqdn = '_acme-challenge.{0}'.format(fqdn)

        # compute sha256 hash
        _hash = b64_url_encode(self.logger, sha256_hash(self.logger, '{0}.{1}'.format(token, jwk_thumbprint)))
        # query dns
        txt = txt_get(self.logger, fqdn)

        # compare computed hash with result from DNS query
        if _hash == txt:
            result = True
        else:
            result = False
        self.logger.debug('Challenge.validate_dns_challenge() ended with: {0}'.format(result))
        return result

    def validate_http_challenge(self, fqdn, token, jwk_thumbprint):
        """ validate http challenge """
        self.logger.debug('Challenge.validate_http_challenge()')

        req = url_get(self.logger, 'http://{0}/.well-known/acme-challenge/{1}'.format(fqdn, token))
        if req:
            if req.splitlines()[0] == '{0}.{1}'.format(token, jwk_thumbprint):
                result = True
            else:
                result = False
        else:
            result = False
        self.logger.debug('Challenge.validate_http_challenge() ended with: {0}'.format(result))
        return result

    def validate_tkauth_challenge(self, tnauthlist, _token, _jwk_thumbprint, payload):
        """ validate tkauth challenge """
        self.logger.debug('Challenge.validate_tkauth_challenge({0}:{1})'.format(tnauthlist, payload))

        result = True
        self.logger.debug('Challenge.validate_tkauth_challenge() ended with: {0}'.format(result))
        return result

    def validate_tnauthlist_payload(self, payload, challenge_dic):
        """ check payload in cae tnauthlist option has been set """
        self.logger.debug('Challenge.validate_tnauthlist_payload({0}:{1})'.format(payload, challenge_dic))

        code = 400
        message = None
        detail = None

        if 'type' in challenge_dic:
            if challenge_dic['type'] == 'tkauth-01':
                self.logger.debug('tkauth identifier found')
                # check if we havegot an atc claim in the challenge request
                if 'atc' in payload:
                    # check if we got a SPC token in the challenge request
                    if not bool(payload['atc']):
                        code = 400
                        message = 'urn:ietf:params:acme:error:malformed'
                        detail = 'SPC token is missing'
                    else:
                        code = 200
                else:
                    code = 400
                    message = 'urn:ietf:params:acme:error:malformed'
                    detail = 'atc claim is missing'
            else:
                code = 200
        else:
            message = 'urn:ietf:params:acme:error:malformed'
            detail = 'invalid challenge: {0}'.format(challenge_dic)

        self.logger.debug('Challenge.validate_tnauthlist_payload() ended with:{0}'.format(code))
        return(code, message, detail)
