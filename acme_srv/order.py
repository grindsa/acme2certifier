#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Order class """
# pylint: disable=c0209
from __future__ import print_function
import json
from acme_srv.helper import b64_url_recode, generate_random_string, load_config, parse_url, uts_to_date_utc, uts_now, error_dic_get
from acme_srv.certificate import Certificate
from acme_srv.db_handler import DBstore
from acme_srv.message import Message


class Order(object):
    """ class for order handling """

    def __init__(self, debug=None, srv_name=None, logger=None):
        self.server_name = srv_name
        self.debug = debug
        self.logger = logger
        self.dbstore = DBstore(self.debug, self.logger)
        self.message = Message(self.debug, self.server_name, self.logger)
        self.error_msg_dic = error_dic_get(self.logger)
        self.validity = 86400
        self.authz_validity = 86400
        self.expiry_check_disable = False
        self.path_dic = {'authz_path': '/acme/authz/', 'order_path': '/acme/order/', 'cert_path': '/acme/cert/'}
        self.retry_after = 600
        self.tnauthlist_support = False

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self._config_load()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def _auth_add(self, oid, payload, auth_dic):
        self.logger.debug('Order._auth_add({0})'.format(oid))

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
                auth['expires'] = uts_now() + self.authz_validity
                try:
                    self.dbstore.authorization_add(auth)
                except Exception as err_:
                    self.logger.critical('acme2certifier database error in Order._add() authz: {0}'.format(err_))
        else:
            error = self.error_msg_dic['malformed']

        self.logger.debug('Order._auth_add() ended with {0}'.format(error))
        return error

    def _add(self, payload, aname):
        """ add order request to database """
        self.logger.debug('Order._add({0})'.format(aname))
        error = None
        auth_dic = {}
        order_name = generate_random_string(self.logger, 12)
        expires = uts_now() + self.validity

        if 'identifiers' in payload:

            data_dic = {'status': 2,
                        'expires': expires,
                        'account': aname}

            data_dic['name'] = order_name
            data_dic['identifiers'] = json.dumps(payload['identifiers'])

            # check identifiers
            error = self._identifiers_check(payload['identifiers'])
            # change order status if needed
            if error:
                data_dic['status'] = 1

            try:
                # add order to db
                oid = self.dbstore.order_add(data_dic)
            except Exception as err_:
                self.logger.critical('acme2certifier database error in Order._add() order: {0}'.format(err_))
                oid = None

            if not error:
                # authorization add
                error = self._auth_add(oid, payload, auth_dic)
        else:
            error = self.error_msg_dic['unsupportedidentifier']

        self.logger.debug('Order._add() ended')
        return (error, order_name, auth_dic, uts_to_date_utc(expires))

    def _config_orderconfig_load(self, config_dic):
        """" load config from file """
        self.logger.debug('Order._config_orderconfig_load()')

        if 'Order' in config_dic:
            self.tnauthlist_support = config_dic.getboolean('Order', 'tnauthlist_support', fallback=False)
            self.expiry_check_disable = config_dic.getboolean('Order', 'expiry_check_disable', fallback=False)
            if 'retry_after_timeout' in config_dic['Order']:
                try:
                    self.retry_after = int(config_dic['Order']['retry_after_timeout'])
                except Exception:
                    self.logger.warning('Order._config_load(): failed to parse retry_after: {0}'.format(config_dic['Order']['retry_after_timeout']))
            if 'validity' in config_dic['Order']:
                try:
                    self.validity = int(config_dic['Order']['validity'])
                except Exception:
                    self.logger.warning('Order._config_load(): failed to parse validity: {0}'.format(config_dic['Order']['validity']))

        self.logger.debug('Order._config_orderconfig_load() ended')

    def _config_load(self):
        """" load config from file """
        self.logger.debug('Order._config_load()')

        config_dic = load_config()
        # load order config
        self._config_orderconfig_load(config_dic)

        if 'Authorization' in config_dic:
            if 'validity' in config_dic['Authorization']:
                try:
                    self.authz_validity = int(config_dic['Authorization']['validity'])
                except Exception:
                    self.logger.warning('Order._config_load(): failed to parse authz validity: {0}'.format(config_dic['Authorization']['validity']))

        if 'Directory' in config_dic and 'url_prefix' in config_dic['Directory']:
            self.path_dic = {k: config_dic['Directory']['url_prefix'] + v for k, v in self.path_dic.items()}

        self.logger.debug('Order._config_load() ended.')

    def _name_get(self, url):
        """ get ordername """
        self.logger.debug('Order._name_get({0})'.format(url))
        url_dic = parse_url(self.logger, url)
        order_name = url_dic['path'].replace(self.path_dic['order_path'], '')
        if '/' in order_name:
            (order_name, _sinin) = order_name.split('/', 1)
        self.logger.debug('Order._name_get() ended')
        return order_name

    def _identifiers_check(self, identifiers_list):
        """ check validity of identifers in order """
        self.logger.debug('Order._identifiers_check({0})'.format(identifiers_list))
        error = None
        allowed_identifers = ['dns']

        # add tnauthlist to list of supported identfiers if configured to do so
        if self.tnauthlist_support:
            allowed_identifers.append('tnauthlist')

        if identifiers_list and isinstance(identifiers_list, list):
            for identifier in identifiers_list:
                if 'type' in identifier:
                    if identifier['type'].lower() not in allowed_identifers:
                        error = self.error_msg_dic['unsupportedidentifier']
                        break
                else:
                    error = self.error_msg_dic['malformed']
        else:
            error = self.error_msg_dic['malformed']

        self.logger.debug('Order._identifiers_check() done with {0}:'.format(error))
        return error

    def _info(self, order_name):
        """ list details of an order """
        self.logger.debug('Order._info({0})'.format(order_name))
        try:
            result = self.dbstore.order_lookup('name', order_name)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Order._info(): {0}'.format(err_))
            result = None
        return result

    def _finalize(self, order_name, payload):
        """ finalize request """
        self.logger.debug('Order._finalize()')

        certificate_name = None
        message = None
        detail = None

        # lookup order-status (must be ready to proceed)
        order_dic = self._info(order_name)
        if 'status' in order_dic and order_dic['status'] == 'ready':
            # update order_status / set to processing
            self._update({'name': order_name, 'status': 'processing'})
            if 'csr' in payload:
                self.logger.debug('CSR found()')
                # this is a new request
                (code, certificate_name, detail) = self._csr_process(order_name, payload['csr'])
                # change status only if we do not have a poll_identifier (stored in detail variable)
                if code == 200:
                    if not detail:
                        # update order_status / set to valid
                        self._update({'name': order_name, 'status': 'valid'})
                elif certificate_name == 'timeout':
                    code = 200
                    message = certificate_name
                else:
                    message = certificate_name
                    detail = 'enrollment failed'
            else:
                code = 400
                message = self.error_msg_dic['badcsr']
                detail = 'csr is missing in payload'
        else:
            code = 403
            message = self.error_msg_dic['ordernotready']
            detail = 'Order is not ready'

        self.logger.debug('Order._finalize() ended')
        return (code, message, detail, certificate_name)

    def _process(self, order_name, protected, payload):
        """ process order """
        self.logger.debug('Order._process({0})'.format(order_name))
        certificate_name = None
        message = None
        detail = None

        if 'url' in protected:
            if 'finalize' in protected['url']:
                # finalize order
                (code, message, detail, certificate_name) = self._finalize(order_name, payload)
            else:
                self.logger.debug('polling request()')
                code = 200
                # this is a polling request; lookup certificate
                try:
                    cert_dic = self.dbstore.certificate_lookup('order__name', order_name)
                except Exception as err_:
                    self.logger.critical('acme2certifier database error in Order._process(): {0}'.format(err_))
                    cert_dic = {}
                if cert_dic:
                    # we found a cert in the database
                    # pylint: disable=R1715
                    if 'name' in cert_dic:
                        certificate_name = cert_dic['name']
        else:
            code = 400
            message = self.error_msg_dic['malformed']
            detail = 'url is missing in protected'

        self.logger.debug('Order._process() ended with order:{0} {1}:{2}:{3}'.format(order_name, code, message, detail))
        return (code, message, detail, certificate_name)

    def _csr_process(self, order_name, csr):
        """ process certificate signing request """
        self.logger.debug('Order._csr_process({0})'.format(order_name))

        order_dic = self._info(order_name)

        if order_dic:
            # change decoding from b64url to b64
            csr = b64_url_recode(self.logger, csr)

            with Certificate(self.debug, self.server_name, self.logger) as certificate:
                certificate_name = certificate.store_csr(order_name, csr)
                if certificate_name:
                    (error, detail) = certificate.enroll_and_store(certificate_name, csr, order_name)
                    if not error:
                        code = 200
                        message = certificate_name
                    else:
                        code = 400
                        message = error
                        if message == self.error_msg_dic['serverinternal']:
                            code = 500
                else:
                    code = 500
                    message = self.error_msg_dic['serverinternal']
                    detail = 'CSR processing failed'
        else:
            code = 400
            message = self.error_msg_dic['unauthorized']
            detail = 'order: {0} not found'.format(order_name)

        self.logger.debug('Order._csr_process() ended with order:{0} {1}:{2}:{3}'.format(order_name, code, message, detail))
        return (code, message, detail)

    def _update(self, data_dic):
        """ update order based on ordername """
        self.logger.debug('Order._update({0})'.format(data_dic))
        try:
            self.dbstore.order_update(data_dic)
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Order._update(): {0}'.format(err_))

    def _order_dic_create(self, tmp_dic):
        """ create order dictionary """
        self.logger.debug('Order._order_dic_create()')

        order_dic = {}
        if 'status' in tmp_dic:
            order_dic['status'] = tmp_dic['status']
        if 'expires' in tmp_dic:
            order_dic['expires'] = uts_to_date_utc(tmp_dic['expires'])
        if 'notbefore' in tmp_dic and tmp_dic['notbefore'] != 0:
            order_dic['notBefore'] = uts_to_date_utc(tmp_dic['notbefore'])
        if 'notafter' in tmp_dic and tmp_dic['notafter'] != 0:
            order_dic['notAfter'] = uts_to_date_utc(tmp_dic['notafter'])
        if 'identifiers' in tmp_dic:
            try:
                order_dic['identifiers'] = json.loads(tmp_dic['identifiers'])
            except Exception:
                self.logger.error('Order._order_dic_create(): error while parsing the identifier {0}'.format(tmp_dic['identifiers']))

        self.logger.debug('Order._order_dic_create() ended')
        return order_dic

    def _authz_list_lookup(self, order_name):
        """ lookup authorization list """
        self.logger.debug('Order._authz_list_lookup({0})'.format(order_name))

        try:
            authz_list = self.dbstore.authorization_lookup('order__name', order_name, ['name', 'status__name'])
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Order._authz_list_lookup(): {0}'.format(err_))
            authz_list = []

        self.logger.debug('Order._authz_list_lookup() ended')
        return authz_list

    def _validity_list_create(self, authz_list, order_dic, order_name):
        self.logger.debug('Order._validity_list_create()')
        validity_list = []
        for authz in authz_list:
            if 'name' in authz:
                order_dic["authorizations"].append('{0}{1}{2}'.format(self.server_name, self.path_dic['authz_path'], authz['name']))
            if 'status__name' in authz:
                if authz['status__name'] == 'valid':
                    validity_list.append(True)
                else:
                    validity_list.append(False)

        # update orders status from pending to ready
        if validity_list and 'status' in order_dic:
            if False not in validity_list and order_dic['status'] == 'pending':
                self._update({'name': order_name, 'status': 'ready'})

        self.logger.debug('Order._lookup() ended')

    def _lookup(self, order_name):
        """ sohw order details based on ordername """
        self.logger.debug('Order._validity_list_create({0})'.format(order_name))
        order_dic = {}

        tmp_dic = self._info(order_name)
        if tmp_dic:

            # create order dictionary and lookup authorizatio list
            order_dic = self._order_dic_create(tmp_dic)
            authz_list = self._authz_list_lookup(order_name)

            if authz_list:
                order_dic["authorizations"] = []

                # collect status of different authorizations in list and update order status
                self._validity_list_create(authz_list, order_dic, order_name)

        self.logger.debug('Order._lookup() ended')
        return order_dic

    def invalidate(self, timestamp=None):
        """ invalidate orders """
        self.logger.debug('Order.invalidate({0})'.format(timestamp))
        if not timestamp:
            timestamp = uts_now()
            self.logger.debug('Order.invalidate(): set timestamp to {0}'.format(timestamp))

        field_list = ['id', 'name', 'expires', 'identifiers', 'created_at', 'status__id', 'status__name', 'account__id', 'account__name', 'account__contact']
        try:
            order_list = self.dbstore.orders_invalid_search('expires', timestamp, vlist=field_list, operant='<=')
        except Exception as err_:
            self.logger.critical('acme2certifier database error in Order._invalidate() search: {0}'.format(err_))
            order_list = []
        output_list = []
        for order in order_list:
            # print(order['id'])
            # select all orders which are not invalid
            if 'name' in order and 'status__name' in order and order['status__name'] != 'invalid':
                # change status and add to output list
                output_list.append(order)
                data_dic = {'name': order['name'], 'status': 'invalid'}
                try:
                    self.dbstore.order_update(data_dic)
                except Exception as err_:
                    self.logger.critical('acme2certifier database error in Order._invalidate() upd: {0}'.format(err_))

        self.logger.debug('Order.invalidate() ended: {0} orders identified'.format(len(output_list)))
        return (field_list, output_list)

    def new(self, content):
        """ new oder request """
        self.logger.debug('Order.new()')

        response_dic = {}
        # check message
        (code, message, detail, _protected, payload, account_name) = self.message.check(content)
        if code == 200:
            (error, order_name, auth_dic, expires) = self._add(payload, account_name)
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
                for auth_name, value in auth_dic.items():
                    response_dic['data']['authorizations'].append('{0}{1}{2}'.format(self.server_name, self.path_dic['authz_path'], auth_name))
                    response_dic['data']['identifiers'].append(value)
            else:
                code = 400
                message = error
                detail = 'could not process order'
        # prepare/enrich response
        status_dic = {'code': code, 'type': message, 'detail': detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug('Order.new() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic

    def _parse(self, protected, payload):
        """ new oder parse """
        self.logger.debug('Order._parse()')

        order_name = certificate_name = None

        if 'url' in protected:
            order_name = self._name_get(protected['url'])
            if order_name:
                order_dic = self._lookup(order_name)
                if order_dic:
                    (code, message, detail, certificate_name) = self._process(order_name, protected, payload)
                else:
                    code = 403
                    message = self.error_msg_dic['ordernotready']
                    detail = 'order not found'
            else:
                code = 400
                message = self.error_msg_dic['malformed']
                detail = 'order name is missing'
        else:
            code = 400
            message = self.error_msg_dic['malformed']
            detail = 'url is missing in protected'

        self.logger.debug('Order._parse() ended with code: {0}'.format(code))
        return (code, message, detail, certificate_name, order_name)

    def parse(self, content):
        """ new oder request """
        self.logger.debug('Order.parse()')

        # invalidate expired orders
        if not self.expiry_check_disable:
            self.invalidate()

        response_dic = {}
        # check message
        (code, message, detail, protected, payload, _account_name) = self.message.check(content)

        if code == 200:

            # parse message
            (code, message, detail, certificate_name, order_name) = self._parse(protected, payload)

            if code == 200:
                # create response
                response_dic['header'] = {}
                response_dic['header']['Location'] = '{0}{1}{2}'.format(self.server_name, self.path_dic['order_path'], order_name)
                response_dic['data'] = self._lookup(order_name)
                if 'status' in response_dic['data'] and response_dic['data']['status'] == 'processing':
                    # set retry header as cert issuane is not completed.
                    response_dic['header']['Retry-After'] = '{0}'.format(self.retry_after)
                response_dic['data']['finalize'] = '{0}{1}{2}/finalize'.format(self.server_name, self.path_dic['order_path'], order_name)
                # add the path to certificate if order-status is ready
                # if certificate_name:
                if certificate_name and 'status' in response_dic['data'] and response_dic['data']['status'] == 'valid':
                    response_dic['data']['certificate'] = '{0}{1}{2}'.format(self.server_name, self.path_dic['cert_path'], certificate_name)

        # prepare/enrich response
        status_dic = {'code': code, 'type': message, 'detail': detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug('Order.parse() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic
