#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca hanlder for Insta Certifier via REST-API class """
from __future__ import print_function
import json
from acme.helper import b64_url_recode, generate_random_string, cert_san_get, cert_tnauthlist_get, uts_now, uts_to_date_utc, load_config, csr_san_get
from acme.ca_handler import CAhandler
from acme.db_handler import DBstore
from acme.message import Message

class Certificate(object):
    """ CA  handler """

    def __init__(self, debug=None, srv_name=None, logger=None):
        self.debug = debug
        self.server_name = srv_name
        self.logger = logger
        self.dbstore = DBstore(self.debug, self.logger)
        self.message = Message(self.debug, self.server_name, self.logger)
        self.path_dic = {'cert_path' : '/acme/cert/'}
        self.tnauthlist_support = False

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        self.load_config()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def enroll_and_store(self, certificate_name, csr):
        """ cenroll and store certificater """
        self.logger.debug('Certificate.enroll_and_store({0},{1})'.format(certificate_name, csr))

        # check csr against order
        csr_check = self.csr_check(certificate_name, csr)

        # TO BE VERIFIED
        csr_check = False
        error = None
        # only continue if there is no error
        if csr_check:
            with CAhandler(self.debug, self.logger) as ca_handler:
                (error, certificate, certificate_raw) = ca_handler.enroll(csr)
                if certificate:
                    result = self.store_cert(certificate_name, certificate, certificate_raw)
                else:
                    result = None
                    # store error message for later analysis
                    self.store_cert_error(certificate_name, error)
        else:
            result = None

        self.logger.debug('Certificate.enroll_and_store() ended with: {0}:{1}'.format(result, error))
        return (result, error)

    def info(self, certificate_name):
        """ get certificate from database """
        self.logger.debug('Certificate.info({0})'.format(certificate_name))
        return self.dbstore.certificate_lookup('name', certificate_name)

    def new_get(self, url):
        """ get request """
        self.logger.debug('Certificate.new_get({0})'.format(url))
        certificate_name = url.replace('{0}{1}'.format(self.server_name, self.path_dic['cert_path']), '')

        response_dic = {}
        # fetch certificate dictionary from DB
        certificate_dic = self.info(certificate_name)

        if 'cert' in certificate_dic:
            response_dic['code'] = 200
            # filter certificate and decode it
            response_dic['data'] = certificate_dic['cert']
            response_dic['header'] = {}
            response_dic['header']['Content-Type'] = 'application/pem-certificate-chain'
        else:
            response_dic['code'] = 403
            response_dic['data'] = 'NotFound'
        self.logger.debug('Certificate.new_get({0}) ended'.format(response_dic))
        return response_dic

    def new_post(self, content):
        """ post request """
        self.logger.debug('Certificate.new_post({0})')

        response_dic = {}
        # check message
        (code, message, detail, protected, _payload, _account_name) = self.message.check(content)
        if code == 200:
            if 'url' in protected:
                response_dic = self.new_get(protected['url'])
            else:
                response_dic['code'] = code = 400
                response_dic['data'] = message = 'urn:ietf:params:acme:error:malformed'
                detail = 'url missing in protected header'
        # prepare/enrich response
        status_dic = {'code': code, 'message' : message, 'detail' : detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug('Certificate.new_post() ended with: {0}'.format(response_dic))
        return response_dic

    def revoke(self, content):
        """ revoke request """
        self.logger.debug('Certificate.revoke()')

        response_dic = {}
        # check message
        (code, message, detail, _protected, payload, account_name) = self.message.check(content)

        if code == 200:
            if 'certificate' in payload:
                (code, error) = self.revocation_request_validate(account_name, payload)
                if code == 200:
                    # revocation starts here
                    # revocation reason is stored in error variable
                    rev_date = uts_to_date_utc(uts_now())
                    with CAhandler(self.debug, self.logger) as ca_handler:
                        (code, message, detail) = ca_handler.revoke(payload['certificate'], error, rev_date)
                else:
                    message = error
                    detail = None

            else:
                # message could not get decoded
                code = 400
                message = 'urn:ietf:params:acme:error:malformed'
                detail = 'certificate not found'

        # prepare/enrich response
        status_dic = {'code': code, 'message' : message, 'detail' : detail}
        response_dic = self.message.prepare_response(response_dic, status_dic)

        self.logger.debug('Certificate.revoke() ended with: {0}'.format(response_dic))
        return response_dic

    def store_cert(self, certificate_name, certificate, raw):
        """ get key for a specific account id """
        self.logger.debug('Certificate.store_cert({0})'.format(certificate_name))
        data_dic = {'cert' : certificate, 'name': certificate_name, 'cert_raw' : raw}
        cert_id = self.dbstore.certificate_add(data_dic)
        self.logger.debug('Certificate.store_cert({0}) ended'.format(cert_id))
        return cert_id

    def store_cert_error(self, certificate_name, error):
        """ get key for a specific account id """
        self.logger.debug('Certificate.store_error({0})'.format(certificate_name))
        data_dic = {'error' : error, 'name': certificate_name}
        cert_id = self.dbstore.certificate_add(data_dic)
        self.logger.debug('Certificate.store_error({0}) ended'.format(cert_id))
        return cert_id

    def store_csr(self, order_name, csr):
        """ get key for a specific account id """
        self.logger.debug('Certificate.store_csr({0})'.format(order_name))
        certificate_name = generate_random_string(self.logger, 12)
        data_dic = {'order' : order_name, 'csr' : csr, 'name': certificate_name}
        self.dbstore.certificate_add(data_dic)
        self.logger.debug('Certificate.store_csr() ended')
        return certificate_name

    def revocation_request_validate(self, account_name, payload):
        """ chec CSR """
        self.logger.debug('Certificate.revocation_request_validate({0})'.format(account_name))

        # set a value to avoid that we are returning none by accident
        code = 400
        error = None
        if 'reason' in payload:
            # check revocatoin reason if we get one
            rev_reason = self.revocation_reason_check(payload['reason'])
            # successful
            if not rev_reason:
                error = 'urn:ietf:params:acme:error:badRevocationReason'
        else:
            # set revocation reason to unspecified
            rev_reason = 'unspecified'

        if rev_reason:
            # check if the account issued the certificate and return the order name
            if 'certificate' in payload:
                order_name = self.account_check(account_name, payload['certificate'])
            else:
                order_name = None

            error = rev_reason
            if order_name:
                # check if the account holds the authorization for the identifiers
                auth_chk = self.authorization_check(order_name, payload['certificate'])
                if auth_chk:
                    # all good set code to 200
                    code = 200
                else:
                    error = 'urn:ietf:params:acme:error:unauthorized'

        self.logger.debug('Certificate.revocation_request_validate() ended with: {0}, {1}'.format(code, error))
        return (code, error)

    def revocation_reason_check(self, reason):
        """ check reason """
        self.logger.debug('Certificate.check_revocation_reason({0})'.format(reason))

        # taken from https://tools.ietf.org/html/rfc5280#section-5.3.1
        allowed_reasons = {
            0 : 'unspecified',
            1 : 'keyCompromise',
            # 2 : 'cACompromise',
            3 : 'affiliationChanged',
            4 : 'superseded',
            5 : 'cessationOfOperation',
            6 : 'certificateHold',
            # 8 : 'removeFromCRL',
            # 9 : 'privilegeWithdrawn',
            # 10 : 'aACompromise'
        }

        result = None
        if reason in allowed_reasons:
            result = allowed_reasons[reason]
        self.logger.debug('Certificate.store_csr() ended with {0}'.format(result))
        return result

    def account_check(self, account_name, certificate):
        """ check account """
        self.logger.debug('Certificate.issuer_check()')
        return self.dbstore.certificate_account_check(account_name, b64_url_recode(self.logger, certificate))

    def authorization_check(self, order_name, certificate):
        """ check if an acount holds authorization for all identifiers = SANs in the certificate """
        self.logger.debug('Certificate.authorization_check()')

        # empty list of statuses
        identifier_status = []

        # get identifiers for order
        identifier_dic = self.dbstore.order_lookup('name', order_name, ['identifiers'])

        if identifier_dic and 'identifiers' in identifier_dic:
            # load identifiers
            try:
                identifiers = json.loads(identifier_dic['identifiers'].lower())
            except BaseException:
                identifiers = []

            # check if we have a tnauthlist identifier
            tnauthlist_identifer_in = self.tnauth_identifier_check(identifiers)

            if self.tnauthlist_support and tnauthlist_identifer_in:
                # reload identifiers (case senetive)
                try:
                    identifiers = json.loads(identifier_dic['identifiers'])
                except BaseException:
                    identifiers = []
                # get list of certextensions in base64 format
                tnauthlist = cert_tnauthlist_get(self.logger, certificate)

                for identifier in identifiers:
                    # get the tnauthlist identifier
                    if identifier['type'].lower() == 'tnauthlist':
                        # check if tnauthlist extension is in extension list
                        if identifier['value'] in tnauthlist:
                            identifier_status.append(True)
                        else:
                            identifier_status.append(False)
            else:
                # get sans
                san_list = cert_san_get(self.logger, certificate)
                identifier_status = self.identifer_status_list(identifiers, san_list)

        result = False
        if identifier_status and False not in identifier_status:
            result = True

        self.logger.debug('Certificate.authorization_check() ended with {0}'.format(result))
        return result

    def load_config(self):
        """" load config from file """
        self.logger.debug('Certificate.load_config()')
        config_dic = load_config()
        if 'Order' in config_dic:
            self.tnauthlist_support = config_dic.getboolean('Order', 'tnauthlist_support', fallback=False)
        self.logger.debug('Certificate.load_config() ended.')

    def tnauth_identifier_check(self, identifier_dic):
        """ check if we have an tnauthlist_identifier """
        self.logger.debug('Certificate.tnauth_identifier_check()')
        # check if we have a tnauthlist identifier
        tnauthlist_identifer_in = False
        for identifier in identifier_dic:
            if 'type' in identifier:
                if identifier['type'].lower() == 'tnauthlist':
                    tnauthlist_identifer_in = True
        self.logger.debug('Certificate.tnauth_identifier_check() ended with: {0}'.format(tnauthlist_identifer_in))
        return tnauthlist_identifer_in

    def csr_check(self, certificate_name, csr):
        """ compare csr extensions against order """
        self.logger.debug('Certificate.csr_check()')
        
        # fetch certificate dictionary from DB
        certificate_dic = self.info(certificate_name)

        # empty list of statuses
        identifier_status = []

        if 'order' in certificate_dic:
            # get identifiers for order
            identifier_dic = self.dbstore.order_lookup('name', certificate_dic['order'], ['identifiers'])

            if identifier_dic and 'identifiers' in identifier_dic:
                # load identifiers
                try:
                    identifiers = json.loads(identifier_dic['identifiers'].lower())
                except BaseException:
                    identifiers = []

                tnauthlist_identifer_in = self.tnauth_identifier_check(identifiers)

                if self.tnauthlist_support and tnauthlist_identifer_in:
                    # reload identifiers (case senetive)
                    try:
                        identifiers = json.loads(identifier_dic['identifiers'])
                    except BaseException:
                        identifiers = []
                else:
                    # get sans
                    san_list = csr_san_get(self.logger, csr)
                    identifier_status = self.identifer_status_list(identifiers, san_list)

        else:
            result = 'error'

        result = False
        if identifier_status and False not in identifier_status:
            result = True

        self.logger.debug('Certificate.csr_check() ended with {0}'.format(result))
        return result

    def identifer_status_list(self, identifiers, san_list):
        """ compare identifiers and check if each san is in identifer list """
        self.logger.debug('Certificate.identifer_status_list()')

        identifier_status = []
        for san in san_list:
            san_is_in = False
            try:
                (cert_type, cert_value) = san.lower().split(':')
            except BaseException:
                cert_type = None
                cert_value = None

            if cert_type and cert_value:
                for identifier in identifiers:
                    if (identifier['type'].lower() == cert_type and identifier['value'].lower() == cert_value):
                        san_is_in = True
                        break
            self.logger.debug('SAN check for {0} against identifiers returned {1}'.format(san.lower(), san_is_in))
            identifier_status.append(san_is_in)

        self.logger.debug('Certificate.identifer_status_list() ended with {0}'.format(identifier_status))
        return identifier_status
