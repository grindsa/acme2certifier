#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Order class """
from __future__ import print_function
import json
from acme.account import Account
from acme.db_handler import DBstore
from acme.challenge import Challenge
from acme.error import Error
from acme.helper import decode_message, generate_random_string, print_debug, uts_now
from acme.nonce import Nonce
from acme.signature import Signature

class Authorization(object):
    """ class for order handling """

    def __init__(self, debug=None, srv_name=None, expiry=86400):
        self.server_name = srv_name
        self.debug = debug
        self.account = Account(self.debug, self.server_name)
        self.dbstore = DBstore(self.debug)
        self.nonce = Nonce(self.debug)
        self.error = Error(self.debug)
        self.signature = Signature(self.debug)
        self.expiry = expiry
        self.authz_path = 'acme/authz'
        self.order_path = 'acme/order'

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def authz_info(self, url):
        """ return authzs information """
        authz_name = url.replace('{0}/{1}/'.format(self.server_name, self.authz_path), '')

        expires = uts_now() + self.expiry
        token = generate_random_string(self.debug, 22)
        # update authorization with expiry date and token (just to be sure)
        self.dbstore.authorization_update({'name' : authz_name, 'token' : token, 'expires' : expires})

        authz_info_dic = {}
        authz_info_dic['status'] = 'pending'
        authz_info_dic['expires'] = expires
        authz_info_dic['identifier'] = self.dbstore.authorization_lookup('name', authz_name)
        challenge = Challenge(self.debug, self.server_name, expires)
        authz_info_dic['identifier']['challenges'] = challenge.new_set(authz_name, token)

        print_debug(self.debug, 'Authorization.authz_info() returns: {0}'.format(json.dumps(authz_info_dic)))
        return authz_info_dic

    def new_get(self, url):
        """ challenge computation based on get request """
        print_debug(self.debug, 'Authorization.new_get()')
        return self.authz_info(url)

    def new_post(self, content):
        """ challenge computation based on post request """
        print_debug(self.debug, 'Authorization.new_post()')
        (result, error_detail, protected_decoded, payload_decoded, _signature) = decode_message(self.debug, content)
        response_dic = {}

        if result:
            # nonce check
            (code, message, _detail) = self.nonce.check(protected_decoded)
            if not message:
                aid = self.account.id_get(protected_decoded)
                (sig_check, error, error_detail) = self.signature.check(content, aid)
                if sig_check:
                    print(payload_decoded)
                else:
                    code = 403
                    message = error
                    detail = error_detail
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:malformed'
            detail = error_detail

        # enrich response dictionary with error details
        #if not code == 201:
        #    if detail:
        #        # some error occured get details
        #        detail = self.error.enrich_error(message, detail)
        #        response_dic['data'] = {'status':code, 'message':message, 'detail': detail}
        #    else:
        #        response_dic['data'] = {'status':code, 'message':message, 'detail': None}
        #else:
        #    # add nonce to header
        #    header_dic['Replay-Nonce'] = self.nonce.generate_and_add()

        # create response
        #response_dic['code'] = code
        #response_dic['header'] = header_dic
        #print_debug(self.debug, 'Order.new() returns: {0}'.format(json.dumps(response_dic)))

        return response_dic
