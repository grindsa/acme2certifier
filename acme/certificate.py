#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca hanlder for Insta Certifier via REST-API class """
from __future__ import print_function
from acme.helper import b64_encode, b64decode_pad, generate_random_string, print_debug
from acme.ca_handler import CAhandler
from acme.db_handler import DBstore
from acme.message import Message

class Certificate(object):
    """ CA  handler """

    def __init__(self, debug=None, srv_name=None):
        self.debug = debug
        self.server_name = srv_name
        self.dbstore = DBstore(self.debug)
        self.message = Message(self.debug, self.server_name)
        self.path = '/acme/cert/'

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def enroll(self, csr):
        """ get key for a specific order """
        print_debug(self.debug, 'Certificate.enroll()')
        cert_bundle = None
        error = None
        with CAhandler(self.debug) as ca_handler:
            cert_dic = ca_handler.enroll(csr)
            if cert_dic:
                if 'status' in cert_dic:
                    # this is an error
                    error = cert_dic['message']
                elif 'certificateBase64' in cert_dic:
                    # this is a valid cert generate the bundle
                    cert_bundle = ca_handler.generate_pem_cert_chain(cert_dic)
                else:
                    error = 'no certificate information found'
            else:
                error = 'internal error'
        print_debug(self.debug, 'Certificate.enroll() ended')
        return(error, cert_bundle)

    def enroll_and_store(self, certificate_name, csr):
        """ get key for a specific order """
        print_debug(self.debug, 'Certificate.enroll_and_store({0},{1})'.format(certificate_name, csr))
        (error, certificate) = self.enroll(csr)
        if certificate:
            result = self.store_cert(certificate_name, certificate)
        else:
            result = None
            # store error message for later analysis
            self.store_cert_error(certificate_name, error)

        print_debug(self.debug, 'Certificate.enroll_and_store() ended with: {0}:{1}'.format(result, error))
        return (result, error)

    def info(self, certificate_name):
        """ get certificate from database """
        print_debug(self.debug, 'Certificate.info({0})'.format(certificate_name))
        return self.dbstore.certificate_lookup('name', certificate_name)

    def new_get(self, url):
        """ get request """
        print_debug(self.debug, 'Certificate.new_get({0})'.format(url))
        certificate_name = url.replace('{0}{1}'.format(self.server_name, self.path), '')

        response_dic = {}
        # fetch certificate dictionary from DB
        certificate_dic = self.info(certificate_name)

        if 'cert' in certificate_dic:
            response_dic['code'] = 200
            # filter certificate and decode it
            response_dic['data'] = b64decode_pad(self.debug, certificate_dic['cert'])
            response_dic['header'] = {}
            response_dic['header']['Content-Type'] = 'application/pem-certificate-chain'
        else:
            response_dic['code'] = 403
            response_dic['data'] = 'NotFound'
        print_debug(self.debug, 'Certificate.new_get({0}) ended'.format(response_dic))
        return response_dic

    def new_post(self, content):
        """ post request """
        print_debug(self.debug, 'Certificate.new_post({0})')

        response_dic = {}
        # check message
        (code, message, detail, protected, _payload) = self.message.check(content)
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

        print_debug(self.debug, 'Certificate.new_post() ended with: {0}'.format(response_dic))
        return response_dic

    def store_cert(self, certificate_name, certificate):
        """ get key for a specific account id """
        print_debug(self.debug, 'Certificate.store_cert({0})'.format(certificate_name))
        data_dic = {'cert' : b64_encode(self.debug, certificate), 'name': certificate_name}
        cert_id = self.dbstore.certificate_add(data_dic)
        print_debug(self.debug, 'Certificate.store_cert({0}) ended'.format(cert_id))
        return cert_id

    def store_cert_error(self, certificate_name, error):
        """ get key for a specific account id """
        print_debug(self.debug, 'Certificate.store_error({0})'.format(certificate_name))
        data_dic = {'error' : error, 'name': certificate_name}
        cert_id = self.dbstore.certificate_add(data_dic)
        print_debug(self.debug, 'Certificate.store_error({0}) ended'.format(cert_id))
        return cert_id

    def store_csr(self, order_name, csr):
        """ get key for a specific account id """
        print_debug(self.debug, 'Certificate.store_csr({0})'.format(order_name))
        certificate_name = generate_random_string(self.debug, 12)
        data_dic = {'order' : order_name, 'csr' : csr, 'name': certificate_name}
        self.dbstore.certificate_add(data_dic)
        print_debug(self.debug, 'Certificate.store_csr() ended')
        return certificate_name
