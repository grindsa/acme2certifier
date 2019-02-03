#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Order class """
from __future__ import print_function
import json
from acme.helper import b64_url_recode, generate_random_string, parse_url, print_debug, uts_to_date_utc, uts_now, validate_csr
from acme.certificate import Certificate
from acme.db_handler import DBstore
from acme.message import Message

class Order(object):
    """ class for order handling """

    def __init__(self, debug=None, srv_name=None, expiry=86400):
        self.server_name = srv_name
        self.debug = debug
        self.dbstore = DBstore(self.debug)
        self.message = Message(self.debug, self.server_name)
        self.expiry = expiry
        self.path_dic = {'authz_path' : '/acme/authz/', 'order_path' : '/acme/order/', 'cert_path' : '/acme/cert/'}

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
                    auth['status'] = 'pending'
                    self.dbstore.authorization_add(auth)
            else:
                error = 'urn:ietf:params:acme:error:malformed'

        else:
            error = 'urn:ietf:params:acme:error:unsupportedIdentifier'

        # print(auth_dic)
        return(error, order_name, auth_dic, uts_to_date_utc(expires))

    def name_get(self, url):
        """ get ordername """
        print_debug(self.debug, 'Order.get_name({0})'.format(url))
        url_dic = parse_url(self.debug, url)
        order_name = url_dic['path'].replace(self.path_dic['order_path'], '')
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

        response_dic = {}
        # check message
        (code, message, detail, _protected, payload, account_name) = self.message.check(content)
        if code == 200:
            (error, order_name, auth_dic, expires) = self.add(payload, account_name)
            if not error:
                code = 201
                response_dic['header'] = {}
                response_dic['header']['Location'] = '{0}{1}{2}'.format(self.server_name, self.path_dic['order_path'], order_name)
                response_dic['data'] = {}
                response_dic['data']['identifiers'] = []
                response_dic['data']['authorizations'] = []
                response_dic['data']['status'] = 'pending'
                response_dic['data']['expires'] = expires
                response_dic['data']['finalize'] = '{0}{1}{2}/finalize'.format(self.server_name, self.path_dic['order_path'], order_name)
                for auth_name in auth_dic:
                    response_dic['data']['authorizations'].append('{0}{1}{2}'.format(self.server_name, self.path_dic['authz_path'], auth_name))
                    response_dic['data']['identifiers'].append(auth_dic[auth_name])
            else:
                code = 400
                message = error
                detail = 'could not process order'
        # prepare/enrich response
        status_dic = {'code': code, 'message' : message, 'detail' : detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        print_debug(self.debug, 'Order.new() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic

    def parse(self, content):
        """ new oder request """
        print_debug(self.debug, 'Order.parse()')

        response_dic = {}
        # check message
        (code, message, detail, protected, payload, _account_name) = self.message.check(content)
        if code == 200:
            if 'url' in protected:
                order_name = self.name_get(protected['url'])
                if 'finalize' in protected['url']:
                    print_debug(self.debug, 'finalize request()')
                    if  'csr' in payload:
                        print_debug(self.debug, 'CSR found()')
                        # this is a new request
                        (code, certificate_name, detail) = self.process_csr(order_name, payload['csr'])
                        if code == 200:
                            # update order_status / set to valid
                            self.update({'name' : order_name, 'status': 'valid'})
                        else:
                            print_debug(self.debug, 'no CSR found()')
                            code = 400
                            message = 'urn:ietf:params:acme:error:badCSR'
                            detail = 'enrollment failed'
                    else:
                        code = 400
                        message = 'urn:ietf:params:acme:error:badCSR'
                        detail = 'csr is missing in payload'
                else:
                    print_debug(self.debug, 'polling request()')
                    # this is a polling request:
                    cert_dic = self.dbstore.certificate_lookup('order__name', order_name)
                    # we found a cert in the database
                    if cert_dic:
                        code = 200
                        certificate_name = cert_dic['name']
                    else:
                        code = 400
                        message = 'urn:ietf:params:acme:error:serverInternal'
                        detail = 'no certificate for order: {0} found'.format(order_name)
            else:
                code = 400
                message = 'urn:ietf:params:acme:error:malformed'
                detail = 'url is missing in protected'

            if code == 200:
                # create response
                response_dic['header'] = {}
                response_dic['header']['Location'] = '{0}{1}{2}'.format(self.server_name, self.path_dic['order_path'], order_name)
                response_dic['data'] = self.lookup(order_name)
                response_dic['data']['finalize'] = '{0}{1}{2}/finalize'.format(self.server_name, self.path_dic['order_path'], order_name)
                response_dic['data']['certificate'] = '{0}{1}{2}'.format(self.server_name, self.path_dic['cert_path'], certificate_name)

        # prepare/enrich response
        status_dic = {'code': code, 'message' : message, 'detail' : detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

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
                    (_result, error) = certificate.enroll_and_store(certificate_name, csr)
                    if not error:
                        code = 200
                        message = certificate_name
                        detail = None
                    else:
                        code = 500
                        message = 'urn:ietf:params:acme:error:serverInternal'
                        detail = error
                else:
                    code = 500
                    message = 'urn:ietf:params:acme:error:serverInternal'
                    detail = 'CSR processing failed'
            else:
                code = 403
                message = 'urn:ietf:params:acme:badCSR'
                detail = 'CSR validation failed'

        else:
            code = 400
            message = 'urn:ietf:params:acme:error:unauthorized'
            detail = 'order: {0} not found'.format(order_name)

        print_debug(self.debug, 'Order.process_csr() ended with order:{0} {1}:{2}:{3}'.format(order_name, code, message, detail))
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
        if tmp_dic:
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
                    if 'name' in authz:
                        order_dic["authorizations"].append('{0}{1}/{2}'.format(self.server_name, self.path_dic['authz_path'], authz['name']))

        return order_dic
