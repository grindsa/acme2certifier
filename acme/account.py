#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Account class """
from __future__ import print_function
import json
from acme.helper import decode_message, generate_random_string, print_debug, validate_email
from acme.db_handler import DBstore
from acme.nonce import Nonce
from acme.error import Error
from acme.message import Message
from acme.signature import Signature

class Account(object):
    """ ACME server class """

    server_name = None

    def __init__(self, debug=None, srv_name=None):
        self.server_name = srv_name
        self.debug = debug
        self.nonce = Nonce(self.debug)
        self.error = Error(self.debug)
        self.dbstore = DBstore(self.debug)
        self.message = Message(self.debug, self.server_name)
        self.signature = Signature(self.debug)
        self.path = '/acme/acct/'

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def add(self, content, contact):
        """ prepare db insert and call DBstore helper """
        print_debug(self.debug, 'Account.account_add()')
        account_name = generate_random_string(self.debug, 12)

        # check request
        if 'alg' in content and 'jwk' in content and contact:
            # check jwk
            if 'e' in content['jwk'] and 'kty' in content['jwk'] and 'n' in content['jwk']:
                data_dic = {
                    'name' : account_name,
                    'alg' : content['alg'],
                    'exponent' : content['jwk']['e'],
                    'kty' : content['jwk']['kty'],
                    'modulus' : content['jwk']['n'],
                    'contact' : json.dumps(contact),
                }
                (db_name, new) = self.dbstore.account_add(data_dic)
                print_debug(self.debug, 'god account_name:{0} new:{1}'.format(db_name, new))
                if new:
                    code = 201
                    message = account_name
                else:
                    code = 200
                    message = db_name
                detail = None
            else:
                code = 400
                message = 'urn:ietf:params:acme:error:malformed'
                detail = 'incomplete JSON Web Key'
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:malformed'
            detail = 'incomplete protectedpayload'

        return(code, message, detail)

    def contact_check(self, content):
        """ check contact information from payload"""
        print_debug(self.debug, 'Account.contact_check()')
        code = 200
        message = None
        detail = None
        if 'contact' in content:
            contact_check = validate_email(self.debug, content['contact'])
            if not contact_check:
                # invalidcontact message
                code = 400
                message = 'urn:ietf:params:acme:error:invalidContact'
                detail = ', '.join(content['contact'])
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:invalidContact'
            detail = 'no contacts specified'

        return(code, message, detail)

    def delete(self, aname):
        """ delete account """
        print_debug(self.debug, 'Account.delete({0})'.format(aname))
        result = self.dbstore.account_delete(aname)

        if result:
            code = 200
            message = None
            detail = None
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:accountDoesNotExist'
            detail = 'deletion failed'

        return(code, message, detail)

    def name_get(self, content):
        """ get id for account depricated"""
        print_debug(self.debug, 'Account.name_get()')
        deprecated = True
        return self.message.name_get(content)

    def new(self, content):
        """ generate a new account """
        print_debug(self.debug, 'Account.account_new()')

        (result, error_detail, protected_decoded, payload_decoded, _signature) = decode_message(self.debug, content)

        response_dic = {}
        response_dic['header'] = {}

        if result:

            # nonce check
            (code, message, detail) = self.nonce.check(protected_decoded)

            # onlyReturnExisting check
            if code == 200 and 'onlyReturnExisting' in payload_decoded:
                (code, message, detail) = self.onlyreturnexisting(protected_decoded, payload_decoded)
            else:
                # tos check
                if code == 200:
                    (code, message, detail) = self.tos_check(payload_decoded)

                # contact check
                if code == 200:
                    (code, message, detail) = self.contact_check(payload_decoded)

                # add account to database
                if code == 200:
                    (code, message, detail) = self.add(protected_decoded, payload_decoded['contact'])

        else:
            code = 400
            message = 'urn:ietf:params:acme:error:malformed'
            detail = error_detail

        # enrich response dictionary with details
        if code == 200 or code == 201:
            response_dic['data'] = {}
            if code == 201:
                response_dic['data'] = {
                    'status': 'valid',
                    'contact': payload_decoded['contact'],
                    'orders': '{0}{1}{2}/orders'.format(self.server_name, self.path, message),
                }
            response_dic['header']['Location'] = '{0}{1}{2}'.format(self.server_name, self.path, message)
        else:
            if detail:
                if detail == 'tosfalse':
                    detail = 'Terms of service must be accepted'
                else:
                    # some error occured get details
                    detail = self.error.enrich_error(message, detail)

                response_dic['data'] = {'status':code, 'message':message, 'detail': detail}
            else:
                response_dic['data'] = {'status':code, 'message':message, 'detail': None}

        # add nonce to header
        response_dic['header']['Replay-Nonce'] = self.nonce.generate_and_add()

        # create response
        response_dic['code'] = code
        print_debug(self.debug, 'Account.account_new() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic

    def onlyreturnexisting(self, protected, payload):
        """ check onlyreturnexisting """
        if payload['onlyReturnExisting']:
            code = None
            message = None
            detail = None
            if 'jwk' in protected:
                if 'n' in protected['jwk']:
                    result = self.dbstore.account_lookup('modulus', protected['jwk']['n'])
                    if result:
                        code = 200
                        message = result['name']
                        detail = None
                    else:
                        code = 400
                        message = 'urn:ietf:params:acme:error:accountDoesNotExist'
                        detail = None
                else:
                    code = 400
                    message = 'urn:ietf:params:acme:error:malformed'
                    detail = 'n value missing'
            else:
                code = 400
                message = 'urn:ietf:params:acme:error:malformed'
                detail = 'jwk structure missing'

        else:
            code = 400
            message = 'urn:ietf:params:acme:error:userActionRequired'
            detail = 'onlyReturnExisting must be true'

        return(code, message, detail)

    def parse(self, content):
        """ parse message """
        print_debug(self.debug, 'Account.parse()')

        response_dic = {}
        # check message
        (code, message, detail, protected, payload) = self.message.check(content)
        if code == 200:
            if 'status' in payload:
                if payload['status'].lower() == 'deactivated':
                    account_name = self.message.name_get(protected)
                    (code, message, detail) = self.delete(account_name)
                    if code == 200:
                        response_dic['data'] = payload
                else:
                    code = 400
                    message = 'urn:ietf:params:acme:error:malformed'
                    detail = 'status attribute without sense'
            else:
                code = 400
                message = 'urn:ietf:params:acme:error:malformed'
                detail = 'dont know what to do with this request'
        # prepare/enrich response
        status_dic = {'code': code, 'message' : message, 'detail' : detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        print_debug(self.debug, 'Account.account_parse() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic

    def tos_check(self, content):
        """ check terms of service """
        print_debug(self.debug, 'Account.tos_check()')
        if 'termsOfServiceAgreed' in content:
            print_debug(self.debug, 'tos:{0}'.format(content['termsOfServiceAgreed']))
            if content['termsOfServiceAgreed']:
                code = 200
                message = None
                detail = None
            else:
                code = 403
                message = 'urn:ietf:params:acme:error:userActionRequired'
                detail = 'tosfalse'
        else:
            print_debug(self.debug, 'no tos statement found.')
            code = 403
            message = 'urn:ietf:params:acme:error:userActionRequired'
            detail = 'tosfalse'

        return(code, message, detail)
