#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Challenge class """
from __future__ import print_function
import json
from acme.certificate import Certificate
from acme.ca_handler import CAhandler
from acme.db_handler import DBstore
from acme.helper import convert_byte_to_string, cert_pubkey_get, csr_pubkey_get, cert_der2pem, b64_decode

class Trigger(object):
    """ Challenge handler """

    def __init__(self, debug=None, srv_name=None, logger=None):
        self.debug = debug
        self.server_name = srv_name
        self.logger = logger
        self.dbstore = DBstore(debug, self.logger)

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        # self._config_load()
        return self

    def __exit__(self, *args):
        """ close the connection at the end of the context """

    def _certname_lookup(self, cert_pem):
        """ compared certificate against csr stored in db """
        self.logger.debug('Trigger._certname_lookup()')

        cert_name = None
        order_name = None

        # extract the public key form certificate
        cert_pubkey = cert_pubkey_get(self.logger, cert_pem)
        with Certificate(self.debug, 'foo', self.logger) as certificate:
            # search certificates in status "processing"
            cert_list = certificate.certlist_search('order__status_id', 4, ('name', 'csr', 'order__name'))

            cert_name = None
            for cert in cert_list:
                # extract public key from certificate and compare it with pub from cert
                if cert['csr']:
                    csr_pubkey = csr_pubkey_get(self.logger, cert['csr'])
                    if csr_pubkey == cert_pubkey:
                        cert_name = cert['name']
                        order_name = cert['order__name']                        
                        break
        self.logger.debug('Trigger._certname_lookup() ended with: {0}'.format(cert_name))
        return (cert_name, order_name)

    def _payload_process(self, payload):
        """ process payload """
        self.logger.debug('Trigger._payload_process()')

        with CAhandler(self.debug, self.logger) as ca_handler:

            if payload:
                (error, cert_bundle, cert_raw) = ca_handler.trigger(payload)
                if cert_bundle and cert_raw:
                    # returned cert_raw is in dear format, convert to pem to lookup the pubic key
                    cert_pem = convert_byte_to_string(cert_der2pem(b64_decode(self.logger, cert_raw)))

                    # lookup certificate_name by comparing public keys
                    (certificate_name, order_name) = self._certname_lookup(cert_pem)

                    if certificate_name:
                        data_dic = {'cert' : cert_bundle, 'name': certificate_name, 'cert_raw' : cert_raw}                       
                        cert_id = self.dbstore.certificate_add(data_dic)
                        if order_name:
                            # update order status to 5 (valid)                        
                            self.dbstore.order_update({'name': order_name, 'status': 'valid'})
                        code = 200
                        message = 'OK'
                        detail = None
                    else:
                        code = 400
                        message = 'certificate_name lookup failed'
                        detail = None                   
                else:
                    code = 400
                    message = error
                    detail = None
            else:
                code = 400
                message = 'payload malformed'
                detail = None

        self.logger.debug('Trigger._payload_process() ended with: {0} {1}'.format(code, message))
        return (code, message, detail)

    def parse(self, content):
        """ new oder request """
        self.logger.debug('Trigger.parse()')

        # convert to json structure
        try:
            payload = json.loads(convert_byte_to_string(content))
        except BaseException:
            payload = {}

        if 'payload' in payload:
            if payload['payload']:
                (code, message, detail) = self._payload_process(payload['payload'])
            else:
                code = 400
                message = 'malformed'
                detail = 'payload empty'
        else:
            code = 400
            message = 'malformed'
            detail = 'payload missing'
        response_dic = {}
        # check message


        # prepare/enrich response
        response_dic['header'] = {}
        response_dic['code'] = code
        response_dic['data'] = {'status': code, 'message': message}
        if detail:
            response_dic['data']['detail'] = detail

        self.logger.debug('Trigger.parse() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic
