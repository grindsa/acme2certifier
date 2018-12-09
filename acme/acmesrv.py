#!/usr/bin/python
# -*- coding: utf-8 -*-
""" cgi based acme server for Netguard Certificate manager / Insta certifier """
from __future__ import print_function
import uuid
import base64
import json
import re
from datetime import datetime
from acme.django_handler import DBstore
# from acme.cgi_handler import DBstore

def print_debug(debug, text):
    """ little helper to print debug messages
        args:
            debug = debug flag
            text  = text to print
        returns:
            (text)
    """
    if debug:
        print('{0}: {1}'.format(datetime.now(), text))

def validate_email(debug, contact_list):
    """ validate contact against RFC608"""
    print_debug(debug, 'validate_email()')
    result = True
    pattern = r"\"?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)\"?"
    # check if we got a list or single address
    if isinstance(contact_list, list):
        for contact in contact_list:
            contact = contact.replace('mailto:', '')
            contact = contact.lstrip()
            tmp_result = bool(re.search(pattern, contact))
            print_debug(debug, '# validate: {0} result: {1}'.format(contact, tmp_result))
            if not tmp_result:
                result = tmp_result
    else:
        contact_list = contact_list.replace('mailto:', '')
        contact_list = contact_list.lstrip()
        result = bool(re.search(pattern, contact_list))
        print_debug(debug, '# validate: {0} result: {1}'.format(contact_list, result))

    return result
    
class Directory(object):
    """ class for directory handling """
    def __init__(self, debug=None, srv_name=None):    
        self.server_name = srv_name
        self.debug = debug
        
    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """    
        
    def directory_get(self):
        """ return response to ACME directory call """
        print_debug(self.debug, 'ACMEsrv.directory_get()')
        d_dic = {
            'newNonce': self.server_name + '/acme/newnonce',
            'newAccount': self.server_name + '/acme/newaccount',

            'key-change': self.server_name + '/acme/key-change',
            'new-authz': self.server_name + '/acme/new-authz',
            'meta' : {
                'home': 'https://github.com/grindsa/acme2certifier',
                'author': 'grindsa <grindelsack@gmail.com>',
            },
            'new-cert': self.server_name + '/acme/new-cert',

            'revoke-cert': self.server_name + '/acme/revoke-cert'
        }
        # generate random key in json as recommended by LE
        d_dic[uuid.uuid4().hex] = 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417'
        return d_dic
        

class ACMEsrv(object):
    """ ACME server class """

    server_name = None

    def __init__(self, debug=None, srv_name=None):
        self.server_name = srv_name
        self.debug = debug
        self.dbstore = DBstore(self.debug)

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def account_add(self, content, contact):
        """ prepare db insert and call DBstore helper """
        # check request
        if 'alg' in content and 'jwk' in content:
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
                detail = 'incomplete JSON Web Key '
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:malformed'
            detail = 'incomplete protectedpayload'

        return(code, message, detail)

    def account_new(self, content):
        """ generate a new account """
        print_debug(self.debug, 'ACMEsrv.account_new()')
        try:
            content = json.loads(content)
        except ValueError:
            content = None

        response_dic = {}
        header_dic = {}
        if content and 'protected' in content and 'payload' in content and 'signature' in content:
            # decode the message
            protected_decoded = self.decode_deserialize(content['protected'])
            payload_decoded = self.decode_deserialize(content['payload'])

            # nonce check
            (code, message, detail) = self.nonce_check(protected_decoded)

            # tos check
            if code == 200:
                (code, message, detail) = self.tos_check(payload_decoded)

            # contact check
            if code == 200:
                (code, message, detail) = self.contact_check(payload_decoded)

            # add account to database
            if code == 200:
                (code, message, detail) = self.account_add(protected_decoded, payload_decoded['contact'])

        else:
            code = 400
            message = 'content Json decoding error'
            detail = None

        # enrich response dictionary with details
        if code == 200 or code == 201:
            response_dic['data'] = {
                'status': 'valid',
                'contact': payload_decoded['contact'],
                'orders': '{0}/acme/acct/{1}/orders'.format(self.server_name, message),
            }
            header_dic['Location'] = '{0}/acme/acct/{1}'.format(self.server_name, message)
        else:
            if detail:
                if detail == 'tosfalse':
                    detail = 'Terms of service must be accepted'
                else:
                    # some error occured get details
                    detail = '{0} {1}'.format(self.acme_errormessage(message), detail)
            else:
                response_dic['data'] = {'status':code, 'message':message, 'detail': detail}

        # add nonce to header
        header_dic['Replay-Nonce'] = self.nonce_generate_and_add()

        # create response
        response_dic['code'] = code
        response_dic['header'] = header_dic
        print_debug(self.debug, 'ACMEsrv.account_new() returns: {0}'.format(json.dumps(response_dic)))

        return response_dic

    @staticmethod
    def acme_errormessage(message):
        """ dictionary containing the implemented acme error messages """
        error_dic = {
            'urn:ietf:params:acme:error:badNonce' : 'JWS has invalid anti-replay nonce',
            'urn:ietf:params:acme:error:invalidContact' : 'The provided contact URI was invalid',
            'urn:ietf:params:acme:error:userActionRequired' : '',
            'urn:ietf:params:acme:error:malformed' : '',
        }
        if message:
            return error_dic[message]
        else:
            return None

    def contact_check(self, content):
        """ check contact information from payload"""
        print_debug(self.debug, 'ACMEsrv.contact_check()')
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

    def nonce_check(self, protected_decoded):
        """ check nonce """
        print_debug(self.debug, 'ACMEsrv.check_nonce()')
        if 'nonce' in protected_decoded:
            (code, message, detail) = self.nonce_check_and_delete(protected_decoded['nonce'])
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:badNonce'
            detail = 'NONE'

        return(code, message, detail)


    def nonce_check_and_delete(self, nonce):
        """ check if nonce exists and delete it """
        print_debug(self.debug, 'ACMEsrv.nonce_check_and_delete({0})'.format(nonce))
        if self.dbstore.nonce_check(nonce):
            self.dbstore.nonce_delete(nonce)
            code = 200
            message = None
            detail = None
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:badNonce'
            detail = nonce
        return(code, message, detail)

    def nonce_generate_and_add(self):
        """ generate new nonce and store it """
        print_debug(self.debug, 'ACMEsrv.nonce_generate_and_add()')
        nonce = self.nonce_new()
        print_debug(self.debug, 'got nonce: {0}'.format(nonce))
        _id = self.dbstore.nonce_add(nonce)
        return nonce

    def nonce_new(self):
        """ generate a new nonce """
        print_debug(self.debug, 'ACMEsrv.nonce_new()')
        return uuid.uuid4().hex

    def servername_get(self):
        """ dumb function to return servername """
        print_debug(self.debug, 'ACMEsrv.servername_get()')
        return self.server_name

    def tos_check(self, content):
        """ check terms of service """
        print_debug(self.debug, 'ACMEsrv.tos_check()')
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



    @staticmethod
    def b64decode_pad(string):
        """ b64 decoding and padding of missing "=" """
        string += '=' * (-len(string) % 4)  # restore stripped '='s
        try:
            b64dec = base64.b64decode(string)
        except TypeError:
            b64dec = 'ERR: b64 decoding error'
        return b64dec

    def decode_deserialize(self, string):
        """ decode and deserialize string """
        # b64 decode
        string_decode = self.b64decode_pad(string)
        # deserialize if b64 decoding was successful
        if string_decode and string_decode != 'ERR: b64 decoding error':
            try:
                string_decode = json.loads(string_decode)
            except ValueError:
                string_decode = 'ERR: Json decoding error'

        return string_decode
