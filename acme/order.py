#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Order class """
from __future__ import print_function
import json
from acme.helper import decode_message, generate_random_string, print_debug, uts_to_date_utc, date_to_uts_utc, uts_now
from acme.account import Account
from acme.db_handler import DBstore
from acme.signature import Signature


class Order(object):
    """ class for order handling """

    def __init__(self, debug=None, srv_name=None, expiry=86400):
        self.server_name = srv_name
        self.debug = debug
        self.account = Account(self.debug, srv_name)
        self.dbstore = DBstore(self.debug)
        self.signature = Signature(self.debug)
        self.expiry = expiry

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def add(self, payload, aid):
        """ add order request to database """
        print_debug(self.debug, 'Order.add({0})'.format(aid))
        error = None
        order_name = generate_random_string(self.debug, 12)
        authorization_name = generate_random_string(self.debug, 12)

        if 'identifiers' in payload:

            data_dic = {'status' : 2,
                        'expires' : uts_now(),
                        'account' : int(aid)}


            data_dic['name'] = order_name
            data_dic['identifiers'] = json.dumps(payload['identifiers'])
            if 'notBefore' in payload:
                data_dic['notBefore'] = payload['notBefore']
            if 'notAfter' in payload:
                data_dic['notAfter'] = payload['notAfter']

            order_id = self.dbstore.order_add(data_dic, authorization_name)

        else:
            print('miss')
            error = 'urn:ietf:params:acme:error:unsupportedIdentifier'
            order_id = None

        return(error, order_id, order_name)

    def new(self, content):
        """ new oder request """
        print_debug(self.debug, 'Order.new()')
        (result, error, protected_decoded, payload_decoded, _signature) = decode_message(self.debug, content)
        response_dic = {}
        response_dic['data'] = {}
        header_dic = {}

        if result:
            aid = self.account.id_get(protected_decoded)
            (sig_check, error) = self.signature.check(content, aid)
            if sig_check:
                (error, order_id, order_name) = self.add(payload_decoded, aid)
