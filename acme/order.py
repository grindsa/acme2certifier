#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Order class """
from __future__ import print_function
import json
from acme.helper import b64_url_recode, generate_random_string, load_config, parse_url, uts_to_date_utc, uts_now
from acme.certificate import Certificate
from acme.db_handler import DBstore
from acme.message import Message

class Order(object):
    """ class for order handling """

    def __init__(self, debug=None, srv_name=None, logger=None, expiry=86400):
        self.server_name = srv_name
        self.debug = debug
        self.logger = logger
        self.dbstore = DBstore(self.debug, self.logger)
        self.message = Message(self.debug, self.server_name, self.logger)
        self.expiry = expiry
        self.path_dic = {'authz_path' : '/acme/authz/', 'order_path' : '/acme/order/', 'cert_path' : '/acme/cert/'}
        self.tnauthlist_support = False

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self.load_config()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def add(self, payload, aname):
        """ add order request to database """
        self.logger.debug('Order.add({0})'.format(aname))
        error = None
        auth_dic = {}
        order_name = generate_random_string(self.logger, 12)
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

            # check identifiers
            error = self.identifiers_check(payload['identifiers'])

            # change order status if needed
            if error:
                data_dic['status'] = 1

            # add order to db
            oid = self.dbstore.order_add(data_dic)

            if not error:
                if oid:
                    error = None
                    for auth in payload['identifiers']:
                        # generate name
                        auth_name = generate_random_string(self.logger, 12)
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
        self.logger.debug('Order.get_name({0})'.format(url))
        url_dic = parse_url(self.logger, url)
        order_name = url_dic['path'].replace(self.path_dic['order_path'], '')
        if '/' in order_name:
            (order_name, _sinin) = order_name.split('/', 1)
        return order_name

    def identifiers_check(self, identifiers_list):
        """ check validity of identifers in order """
        self.logger.debug('Order.identifiers_check({0})'.format(identifiers_list))
        error = None
        allowed_identifers = ['dns']

        # add tnauthlist to list of supported identfiers if configured to do so
        if self.tnauthlist_support:
            allowed_identifers.append('tnauthlist')

        if identifiers_list:
            for identifier in identifiers_list:
                if identifier['type'].lower() not in allowed_identifers:
                    error = 'urn:ietf:params:acme:error:unsupportedIdentifier'
                    break
        else:
            error = 'urn:ietf:params:acme:error:malformed'

        self.logger.debug('Order.identifiers_check() done with {0}:'.format(error))
        return error

    def info(self, order_name):
        """ list details of an order """
        self.logger.debug('Order.info({0})'.format(order_name))
        return self.dbstore.order_lookup('name', order_name)

    def new(self, content):
        """ new oder request """
        self.logger.debug('Order.new()')

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

        self.logger.debug('Order.new() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic

    def parse(self, content):
        """ new oder request """
        self.logger.debug('Order.parse()')

        response_dic = {}
        # check message
        (code, message, detail, protected, payload, _account_name) = self.message.check(content)
        if code == 200:
            if 'url' in protected:
                order_name = self.name_get(protected['url'])
                if 'finalize' in protected['url']:
                    self.logger.debug('finalize request()')
                    if  'csr' in payload:
                        self.logger.debug('CSR found()')
                        # this is a new request
                        (code, certificate_name, detail) = self.process_csr(order_name, payload['csr'])
                        if code == 200:
                            # update order_status / set to valid
                            self.update({'name' : order_name, 'status': 'valid'})
                        else:
                            self.logger.debug('no CSR found()')
                            code = 400
                            message = 'urn:ietf:params:acme:error:badCSR'
                            detail = 'enrollment failed'
                    else:
                        code = 400
                        message = 'urn:ietf:params:acme:error:badCSR'
                        detail = 'csr is missing in payload'
                else:
                    self.logger.debug('polling request()')
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

        self.logger.debug('Order.parse() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic

    def process_csr(self, order_name, csr):
        """ process certificate signing request """
        self.logger.debug('Order.process_csr({0})'.format(order_name))

        order_dic = self.info(order_name)

        if order_dic:
            # change decoding from b64url to b64
            csr = b64_url_recode(self.logger, csr)

            with Certificate(self.debug, self.server_name, self.logger) as certificate:
                # certificate = Certificate(self.debug, self.server_name, self.logger)
                certificate_name = certificate.store_csr(order_name, csr)
                if certificate_name:
                    (_result, error, detail) = certificate.enroll_and_store(certificate_name, csr)
                    if not error:
                        code = 200
                        message = certificate_name
                        detail = None
                    else:
                        code = 500
                        message = error

                else:
                    code = 500
                    message = 'urn:ietf:params:acme:error:serverInternal'
                    detail = 'CSR processing failed'
        else:
            code = 400
            message = 'urn:ietf:params:acme:error:unauthorized'
            detail = 'order: {0} not found'.format(order_name)

        self.logger.debug('Order.process_csr() ended with order:{0} {1}:{2}:{3}'.format(order_name, code, message, detail))
        return(code, message, detail)

    def update(self, data_dic):
        """ update order based on ordername """
        self.logger.debug('Order.update({0})'.format(data_dic))
        return self.dbstore.order_update(data_dic)

    def lookup(self, order_name):
        """ sohw order details based on ordername """
        self.logger.debug('Order.show({0})'.format(order_name))
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

    def load_config(self):
        """" load config from file """
        self.logger.debug('Oder.load_config()')
        config_dic = load_config()
        if 'Order' in config_dic:
            self.tnauthlist_support = config_dic.getboolean('Order', 'tnauthlist_support', fallback=False)
        self.logger.debug('Order.load_config() ended.')
