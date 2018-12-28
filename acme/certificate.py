#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca hanlder for Insta Certifier via REST-API class """
from __future__ import print_function
from acme.helper import generate_random_string, print_debug
from acme.db_handler import DBstore

class Certificate(object):
    """ CA  handler """

    def __init__(self, debug=None):
        self.debug = debug
        self.dbstore = DBstore(self.debug)

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def enroll(self, ca_name, csr):
        """ get key for a specific account id """
        print_debug(self.debug, 'Certificate.enroll({0},{1})'.format(ca_name, csr))
        ca_dic = self.get_ca_properties('name', 'ncm_sub_ca')
        cert_dic = {}
        if 'href' in ca_dic:
            data = {'ca' : ca_dic['href'], 'pkcs10' : csr}
            cert_dic = self.api_post(self.api_host + '/v1/requests', data)
        return cert_dic

    def store_csr(self, order_name, csr):
        """ get key for a specific account id """
        print_debug(self.debug, 'Certificate.store_csr({0})'.format(order_name))
        certificate_name = generate_random_string(self.debug, 12)
        data_dic = {'order' : order_name, 'csr' : csr, 'name': certificate_name}
        cert_id = self.dbstore.certificate_add(data_dic)
        return cert_id