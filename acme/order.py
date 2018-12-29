#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Order class """
from __future__ import print_function
import json
from acme.helper import decode_message, b64_url_recode, generate_random_string, parse_url, print_debug, uts_to_date_utc, uts_now, validate_csr
from acme.account import Account
from acme.certificate import Certificate
from acme.db_handler import DBstore
from acme.error import Error
from acme.nonce import Nonce
from acme.signature import Signature

class Order(object):
    """ class for order handling """

    def __init__(self, debug=None, srv_name=None, expiry=86400):
        self.server_name = srv_name
        self.debug = debug
        self.dbstore = DBstore(self.debug)
        self.nonce = Nonce(self.debug)
        self.expiry = expiry
        self.authz_path = '/acme/authz/'
        self.order_path = '/acme/order/'
        self.cert_path = '/acme/cert/'

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def add(self, payload, aname):
        """ add order request to database """
        print_debug(self.debug, 'Order.add({0})'.format(aname))
        error = None
        auth_dic = {}
        order_name = generate_random_string(self.debug, 12)
        expires = uts_now() + self.expiry

        if 'identifiers' in payload:

            data_dic = {'status' : 2,
                        'expires' : expires,
                        'account' : aname}

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

    def get_name(self, url):
        """ get ordername """
        print_debug(self.debug, 'Order.get_name({0})'.format(url))
        url_dic = parse_url(self.debug, url)
        order_name = url_dic['path'].replace(self.order_path, '')
        if '/' in order_name:
            (order_name, _sinin) = order_name.split('/', 1)
        return order_name

    def info(self, order_name):
        """ list details of an order """
        print_debug(self.debug, 'Order.info({0})'.format(order_name))
        return self.dbstore.order_lookup('name', order_name)

    def new(self, content):
        """ new oder request """
        print_debug(self.debug, 'Order.new()')
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
                    (error, order_name, auth_dic, expires) = self.add(payload_decoded, aname)
                    if not error:
                        code = 201
                        response_dic['header']['Location'] = '{0}{1}{2}'.format(self.server_name, self.order_path, order_name)
                        response_dic['data'] = {}
                        response_dic['data']['identifiers'] = []
                        response_dic['data']['authorizations'] = []
                        response_dic['data']['status'] = 'pending'
                        response_dic['data']['expires'] = expires
                        response_dic['data']['finalize'] = '{0}{1}{2}/finalize'.format(self.server_name, self.order_path, order_name)
                        for auth_name in auth_dic:
                            response_dic['data']['authorizations'].append('{0}{1}{2}'.format(self.server_name, self.authz_path, auth_name))
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
                error_message = Error(self.debug)
                detail = error_message.enrich_error(message, detail)
                response_dic['data'] = {'status':code, 'message':message, 'detail': detail}
            else:
                response_dic['data'] = {'status':code, 'message':message, 'detail': None}
        else:
            # add nonce to header
            response_dic['header']['Replay-Nonce'] = self.nonce.generate_and_add()

        # create response
        response_dic['code'] = code
        print_debug(self.debug, 'Order.new() returns: {0}'.format(json.dumps(response_dic)))

        return response_dic

    def parse(self, content):
        """ new oder request """
        print_debug(self.debug, 'Order.parse()')
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
                    order_name = self.get_name(protected_decoded['url'])
                    if 'csr' in payload_decoded:
                        (code, message, detail) = self.process_csr(order_name, payload_decoded['csr'])
                        if code == 200:
                            # update order_status / set to valid
                            response_dic['header']['Location'] = '{0}{1}{2}'.format(self.server_name, self.order_path, order_name)
                            response_dic['data'] = self.lookup(order_name)
                            response_dic['data']['finalize'] = '{0}{1}{2}/finalize'.format(self.server_name, self.order_path, order_name)
                            response_dic['data']['certificate'] = '{0}{1}{2}'.format(self.server_name, self.cert_path, message)
                            print(response_dic)
                        else:
                            code = 400
                            message = 'urn:ietf:params:acme:error:badCSR'
                            detail = 'enrollment failed'
                    else:
                        code = 400
                        message = 'urn:ietf:params:acme:error:badCSR'
                        detail = 'csr is missing in payload'
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

        # create response
        response_dic['code'] = code
        print_debug(self.debug, 'Order.parse() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic

    def process_csr(self, order_name, csr):
        """ process certificate signing request """
        print_debug(self.debug, 'Order.process_csr({0})'.format(order_name))

        order_dic = self.info(order_name)

        if order_dic:
            # change decoding from b64url to b64
            csr = b64_url_recode(self.debug, csr)
            csr_check = validate_csr(self.debug, order_dic, csr)
            if csr_check:
                certificate = Certificate(self.debug)
                certificate_name = certificate.store_csr(order_name, csr)
                if certificate_name:
                    result = certificate.enroll_and_store(certificate_name, csr)
                    if result:
                        code = 200
                        message = certificate_name
                        detail = None

        else:
            code = 400
            message = 'urn:ietf:params:acme:error:unauthorized'
            detail = 'order: {0} not found'.format(order_name)

        return(code, message, detail)

    def update(self, data_dic):
        """ update order based on ordername """
        print_debug(self.debug, 'Order.update({0})'.format(data_dic))
        return self.dbstore.order_update(data_dic)

    def lookup(self, order_name):
        """ sohw order details based on ordername """
        print_debug(self.debug, 'Order.show({0})'.format(order_name))
        order_dic = {}

        tmp_dic = self.info(order_name)
        if 'status' in tmp_dic:
            order_dic['status'] = tmp_dic['status']
        if 'expires' in tmp_dic:
            order_dic['expires'] = uts_to_date_utc(tmp_dic['expires'])
        if 'notbefore' in tmp_dic:
            if tmp_dic['notbefore'] != 0:
                order_dic['notBefore'] = uts_to_date_utc(tmp_dic['notbefore'])
        if 'notafter' in tmp_dic:
            if tmp_dic['notafter'] != 0:
                order_dic['notAfter'] = uts_to_date_utc(tmp_dic['notafter'])
        if 'identifiers' in tmp_dic:
            order_dic['identifiers'] = json.loads(tmp_dic['identifiers'])

        authz_list = self.dbstore.authorization_lookup('order__name', order_name, ['name'])
        if authz_list:
            order_dic["authorizations"] = []
            for authz in authz_list:
                order_dic["authorizations"].append('{0}{1}/{2}'.format(self.server_name, self.authz_path, authz['name']))

        return order_dic
