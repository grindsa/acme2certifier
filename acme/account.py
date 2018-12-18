#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Account class """
from __future__ import print_function
import json
from acme.helper import decode_deserialize, decode_message, print_debug, signature_check, validate_email
from acme.db_handler import DBstore
from acme.nonce import Nonce
from acme.error import Error
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
        self.signature = Signature(self.debug)
        self.path = 'acme/acct'

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def add(self, content, contact):
        """ prepare db insert and call DBstore helper """
        print_debug(self.debug, 'Account.account_add()')
        # check request
        if 'alg' in content and 'jwk' in content and contact:
            # check jwk
            if 'e' in content['jwk'] and 'kty' in content['jwk'] and 'n' in content['jwk']:
                (account_id, new) = self.dbstore.account_add(content['alg'], content['jwk']['e'], content['jwk']['kty'], content['jwk']['n'], json.dumps(contact))
                print_debug(self.debug, 'god account_id:{0} new:{1}'.format(account_id, new))
                if new:
                    code = 201
                else:
                    code = 200
                message = account_id
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

    def delete(self, aid):
        """ delete account """
        print_debug(self.debug, 'Account.delete({0})'.format(aid))
        result = self.dbstore.account_delete(aid)

        if result:
            code = 200
            message = None
            detail = None
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:accountDoesNotExist'
            detail = 'deletion failed'

        return(code, message, detail)

    def id_get(self, content):
        """ get id for account """
        print_debug(self.debug, 'Account.id_get()')
        if 'kid' in content:
            try:
                kid = int(content['kid'].replace('{0}/{1}/'.format(self.server_name, self.path), ''))
            except ValueError:
                kid = None
        else:
            kid = None

        return kid

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
                        message = result
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

    def new(self, content):
        """ generate a new account """
        print_debug(self.debug, 'Account.account_new()')
        try:
            content = json.loads(content)
        except ValueError:
            content = None

        response_dic = {}
        header_dic = {}
        if content and 'protected' in content and 'payload' in content and 'signature' in content:
            # decode the message
            protected_decoded = decode_deserialize(self.debug, content['protected'])
            payload_decoded = decode_deserialize(self.debug, content['payload'])

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
            message = 'content Json decoding error'
            detail = None

        # enrich response dictionary with details
        if code == 200 or code == 201:
            response_dic['data'] = {}
            if code == 201:
                response_dic['data'] = {
                    'status': 'valid',
                    'contact': payload_decoded['contact'],
                    'orders': '{0}/{1}/{2}/orders'.format(self.server_name, self.path, message),
                }
            header_dic['Location'] = '{0}/{1}/{2}'.format(self.server_name, self.path, message)
        else:
            if detail:
                if detail == 'tosfalse':
                    detail = 'Terms of service must be accepted'
                else:
                    # some error occured get details
                    detail = self.enrich_error(message, detail)

                response_dic['data'] = {'status':code, 'message':message, 'detail': detail}
            else:
                response_dic['data'] = {'status':code, 'message':message, 'detail': None}

        # add nonce to header
        header_dic['Replay-Nonce'] = self.nonce.generate_and_add()

        # create response
        response_dic['code'] = code
        response_dic['header'] = header_dic
        print_debug(self.debug, 'Account.account_new() returns: {0}'.format(json.dumps(response_dic)))

        return response_dic

    def enrich_error(self, message, detail):
        """ put some more content into the error messgae """
        print_debug(self.debug, 'Account.enrich_error()')
        if message and self.error.acme_errormessage(message):
            detail = '{0} {1}'.format(self.error.acme_errormessage(message), detail)
        else:
            detail = '{0}{1}'.format(self.error.acme_errormessage(message), detail)

        return detail

    def parse(self, content):
        """ parse message """
        print_debug(self.debug, 'Account.parse()')
        (result, error, protected_decoded, payload_decoded, _signature) = decode_message(self.debug, content)

        response_dic = {}
        response_dic['data'] = {}
        header_dic = {}
        if result:
            aid = self.id_get(protected_decoded)
            (sig_check, error) = self.signature.check(content, aid)
            if sig_check:
                if 'status' in payload_decoded:
                    if payload_decoded['status'].lower() == 'deactivated':
                        (code, message, detail) = self.delete(aid)
                        if code == 200:
                            response_dic['data'] = payload_decoded
                    else:
                        code = 400
                        message = 'urn:ietf:params:acme:error:malformed'
                        detail = 'status attribute without sense'
                else:
                    code = 400
                    message = 'urn:ietf:params:acme:error:malformed'
                    detail = 'dont know what to do with this request'
            else:
                code = 403
                message = error
                detail = None
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:malformed'
            detail = error

        # enrich response dictionary with details
        if not code == 200:
            if detail:
                # some error occured get details
                detail = self.enrich_error(message, detail)
                response_dic['data'] = {'status':code, 'message':message, 'detail': detail}
            else:
                response_dic['data'] = {'status':code, 'message':message, 'detail': None}

        # create response
        response_dic['code'] = code
        response_dic['header'] = header_dic
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

