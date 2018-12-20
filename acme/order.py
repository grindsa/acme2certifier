#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Order class """
from __future__ import print_function
import json
from acme.helper import decode_message, generate_random_string, print_debug, uts_to_date_utc, uts_now
from acme.account import Account
from acme.db_handler import DBstore
from acme.error import Error
from acme.nonce import Nonce
from acme.signature import Signature

class Order(object):
    """ class for order handling """

    def __init__(self, debug=None, srv_name=None, expiry=86400):
        self.server_name = srv_name
        self.debug = debug
        self.account = Account(self.debug, srv_name)
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

    def add(self, payload, aid):
        """ add order request to database """
        print_debug(self.debug, 'Order.add({0})'.format(aid))
        error = None
        auth_dic = {}
        order_name = generate_random_string(self.debug, 12)
        expires = uts_now() + self.expiry

        if 'identifiers' in payload:

            data_dic = {'status' : 2,
                        'expires' : expires,
                        'account' : int(aid)}

            data_dic['name'] = order_name
            data_dic['identifiers'] = json.dumps(payload['identifiers'])

            #if 'notBefore' in payload:
            #    data_dic['notbefore'] = payload['notBefore']
            #if 'notAfter' in payload:
            #    data_dic['notafter'] = payload['notAfter']

            oid = self.dbstore.order_add(data_dic)
            if oid:
                error = None
                for auth in payload['identifiers']:
                    # generate name
                    auth_name = generate_random_string(self.debug, 12)
                    # print(auth_name, auth)
                    # store to return to upper func
                    auth_dic[auth_name] = auth.copy()
                    auth['name'] = auth_name
                    auth['order'] = oid
                    self.dbstore.authorization_add(auth)
            else:
                error = 'urn:ietf:params:acme:error:malformed'

        else:
            error = 'urn:ietf:params:acme:error:unsupportedIdentifier'

        # print(auth_dic)
        return(error, order_name, auth_dic, uts_to_date_utc(expires))

    def new(self, content):
        """ new oder request """
        print_debug(self.debug, 'Order.new()')
        (result, error_detail, protected_decoded, payload_decoded, _signature) = decode_message(self.debug, content)

        response_dic = {}
        header_dic = {}

        if result:
            # nonce check
            (code, message, detail) = self.nonce.check(protected_decoded)
            if not message:
                aid = self.account.id_get(protected_decoded)
                (sig_check, error, error_detail) = self.signature.check(content, aid)
                if sig_check:
                    (error, order_name, auth_dic, expires) = self.add(payload_decoded, aid)
                    if not error:
                        code = 201
                        header_dic['Location'] = '{0}/{1}/{2}'.format(self.server_name, self.order_path, order_name)
                        response_dic['data'] = {}
                        response_dic['data']['identifiers'] = []
                        response_dic['data']['authorizations'] = []
                        response_dic['data']['status'] = 'pending'
                        response_dic['data']['expires'] = expires
                        response_dic['data']['finalize'] = '{0}/{1}/{2}/finalize'.format(self.server_name, self.order_path, order_name)
                        for auth_name in auth_dic:
                            response_dic['data']['authorizations'].append('{0}/{1}/{2}'.format(self.server_name, self.authz_path, auth_name))
                            response_dic['data']['identifiers'].append(auth_dic[auth_name])
                    else:
                        code = 400
                        message = error
                        detail = 'dont know what to do with this request'
                else:
                    code = 403
                    message = error
                    detail = error_detail
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:malformed'
            detail = error_detail

        # enrich response dictionary with error details
        if not code == 201:
            if detail:
                # some error occured get details
                detail = self.error.enrich_error(message, detail)
                response_dic['data'] = {'status':code, 'message':message, 'detail': detail}
            else:
                response_dic['data'] = {'status':code, 'message':message, 'detail': None}
        else:
            # add nonce to header
            header_dic['Replay-Nonce'] = self.nonce.generate_and_add()

        # create response
        response_dic['code'] = code
        response_dic['header'] = header_dic
        print_debug(self.debug, 'Order.new() returns: {0}'.format(json.dumps(response_dic)))

        return response_dic
