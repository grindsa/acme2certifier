#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Signature class """
from __future__ import print_function
import json
from acme.helper import decode_message, generate_random_string, print_debug
from acme.account import Account
from acme.db_handler import DBstore
from acme.error import Error
from acme.nonce import Nonce
from acme.signature import Signature

class Challenge(object):
    """ Challenge handler """

    def __init__(self, debug=None, srv_name=None, expiry=3600):
        self.debug = debug
        self.server_name = srv_name
        self.dbstore = DBstore(self.debug)
        self.nonce = Nonce(self.debug)
        self.expiry = expiry
        self.path = '/acme/chall/'
        self.authz_path = '/acme/authz/'

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ close the connection at the end of the context """

    def get(self, url):
        """ get challenge details based on get request """
        print_debug(self.debug, 'challenge.new_get({0})'.format(url))
        challenge_name = url.replace('{0}{1}'.format(self.server_name, self.path), '')
        response_dic = {}
        response_dic['code'] = 200
        response_dic['data'] = self.info(challenge_name)
        return response_dic

    def info(self, challenge_name):
        """ get challenge details """
        print_debug(self.debug, 'Challenge.info({0})'.format(challenge_name))
        challenge_dic = self.dbstore.challenge_lookup('name', challenge_name)
        return challenge_dic

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
            challenge_dic['url'] = '{0}{1}{2}'.format(self.server_name, self.path, challenge_name)
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

    def parse(self, url, content):
        """ new oder request """
        print_debug(self.debug, 'Challenge.parse({0})'.format(url))
        (result, error_detail, protected_decoded, payload_decoded, _signature) = decode_message(self.debug, content)

        response_dic = {}
        response_dic['header'] = {}

        if result:
            # nonce check
            (code, message, detail) = self.nonce.check(protected_decoded)
            if not message:
                account = Account(self.debug, self.server_name)
                aname = account.name_get(protected_decoded)
                signature = Signature(self.debug)
                (sig_check, error, error_detail) = signature.check(content, aname)
                if sig_check:
                    challenge_name = url.replace('{0}{1}'.format(self.server_name, self.path), '')
                    if challenge_name:
                        challenge_dic = self.info(challenge_name)
                        # update challenge state to 'processing' - i am not so sure about this
                        # self.update({'name' : challenge_name, 'status' : 4})
                        # start validation
                        self.validate(challenge_name, payload_decoded)
                        if challenge_dic:
                            response_dic['data'] = {}
                            challenge_dic['url'] = url
                            code = 200
                            response_dic['data'] = {}
                            response_dic['data'] = challenge_dic
                        else:
                            code = 400
                            message = 'urn:ietf:params:acme:error:malformed'
                            detail = 'invalid challenge:{0}'.format(challenge_name)
                    else:
                        code = 400
                        message = 'urn:ietf:params:acme:error:malformed'
                        detail = None
                else:
                    code = 403
                    message = error
                    detail = error_detail
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:malformed'
            detail = error_detail

        # enrich response dictionary with error details
        if not code == 200:
            if detail:
                # some error occured get details
                error_message = Error(self.debug)
                detail = error_message.enrich_error(message, detail)
                response_dic['data'] = {'status':code, 'message':message, 'detail': detail}
            else:
                response_dic['data'] = {'status':code, 'message':message, 'detail': None}
        else:
            # add nonce to header
            response_dic['header']['Replay-Nonce'] = self.nonce.generate_and_add()
            # create up-link rel
            response_dic['header']['Link'] = '<{0}{1}>;rel="up"'.format(self.server_name, self.authz_path)

        # create response
        response_dic['code'] = code
        print_debug(self.debug, 'challenge.parse() returns: {0}'.format(json.dumps(response_dic)))

        return response_dic

    def update(self, data_dic):
        """ update challenge """
        print_debug(self.debug, 'Challenge.update({0})'.format(data_dic))
        self.dbstore.challenge_update(data_dic)

    def validate(self, challenge_name, payload):
        """ validate challenge"""
        print_debug(self.debug, 'Challenge.validate({0}: {1})'.format(challenge_name, payload))
        print_debug(self.debug, 'CHALLENGE VALIDATION DISABLED. SETTING challenge status to valid')
        self.update({'name' : challenge_name, 'status' : 5})

        if 'keyAuthorization' in payload:
            data_dic = {'name' : challenge_name, 'keyauthorization' : payload['keyAuthorization']}
            self.update(data_dic)
