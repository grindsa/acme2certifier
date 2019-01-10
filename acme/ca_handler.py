#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca hanlder for Insta Certifier via REST-API class """
from __future__ import print_function
import textwrap
import requests
from requests.auth import HTTPBasicAuth
from acme.helper import load_config, print_debug

class CAhandler(object):
    """ CA  handler """

    def __init__(self, debug=None):
        self.debug = debug
        self.api_host = None
        self.api_user = None
        self.api_password = None
        self.ca_name = None
        self.auth = None

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
        if not self.api_host:
            self.load_config()
            self.set_auth()
        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def api_post(self, url, data):
        """
        generic wrapper for an API post call
        args:
            url - API URL
            data - data to post
        returns:
            result of the post command
        """
        try:
            api_response = requests.post(url=url, json=data, auth=self.auth, verify=False).json()
        except BaseException as err:
            api_response = err

        return api_response

    def enroll(self, csr):
        """ get key for a specific account id """
        print_debug(self.debug, 'CAhandler.enroll({0})'.format(csr))
        ca_dic = self.get_ca_properties('name', self.ca_name)
        cert_dic = {}

        if 'href' in ca_dic:
            # data = {'ca' : ca_dic['href'], 'pkcs10' : csr}
            data = {'ca' : ca_dic['href'], 'pkcs10' : csr}
            cert_dic = self.api_post(self.api_host + '/v1/requests', data)

        if not cert_dic:
            cert_dic = ca_dic

        print_debug(self.debug, 'CAhandler.enroll() ended with: {0}'.format(cert_dic))
        return cert_dic

    def get_ca(self, filter_key=None, filter_value=None):
        """ get list of CAs"""
        print_debug(self.debug, 'get_ca({0}:{1})'.format(filter_key, filter_value))
        params = {}

        if filter_key:
            params['q'] = '{0}:{1}'.format(filter_key, filter_value)
        try:
            api_response = requests.get(self.api_host + '/v1/cas', auth=self.auth, params=params, verify=False).json()
        except BaseException as err:
            api_response = {'status': 500, 'message': str(err), 'statusMessage': 'Internal Server Error'}

        print_debug(self.debug, 'CAhandler.get_ca() ended with: {0}'.format(api_response))
        return api_response

    def get_ca_properties(self, filter_key, filter_value):
        """ get properties for a single CAs"""
        print_debug(self.debug, 'get_ca_properties({0}:{1})'.format(filter_key, filter_value))
        ca_list = self.get_ca(filter_key, filter_value)
        ca_dic = {}
        if 'status' in ca_list and 'message' in ca_list:
            # we got an error from get_ca()
            ca_dic = ca_list
        elif 'cas' in ca_list:
            for cas in ca_list['cas']:
                if cas[filter_key] == filter_value:
                    ca_dic = cas
                    break
        if not ca_dic:
            ca_dic = {'status': 404, 'message': 'CA could not be found', 'statusMessage': 'Not Found'}
        print_debug(self.debug, 'CAhandler.get_ca_properties() ended with: {0}'.format(ca_dic))
        return ca_dic

    def generate_pem_cert_chain(self, cert_dic):
        """ build certificate chain based """
        pem_list = []
        issuer_loop = True

        while issuer_loop:
            if 'certificateBase64' in cert_dic:
                pem_list.append(cert_dic['certificateBase64'])
            else:
                # stop if there is no pem content in the json response
                issuer_loop = False
                break
            if 'issuer' in cert_dic or 'issuerCa' in cert_dic:
                if 'issuer' in cert_dic:
                    print_debug(self.debug, 'issuer found: {0}'.format(cert_dic['issuer']))
                    ca_cert_dic = requests.get(cert_dic['issuer'], auth=self.auth, verify=False).json()
                else:
                    print_debug(self.debug, 'issuer found: {0}'.format(cert_dic['issuerCa']))
                    ca_cert_dic = requests.get(cert_dic['issuerCa'], auth=self.auth, verify=False).json()

                cert_dic = {}
                if 'certificates' in ca_cert_dic:
                    if 'active' in ca_cert_dic['certificates']:
                        cert_dic = requests.get(ca_cert_dic['certificates']['active'], auth=self.auth, verify=False).json()
            else:
                issuer_loop = False
                break

        pem_file = ''
        for cert in pem_list:
            pem_file = '{0}-----BEGIN CERTIFICATE-----\n{1}\n-----END CERTIFICATE-----\n'.format(pem_file, textwrap.fill(cert, 64))

        print_debug(self.debug, 'CAhandler.generate_pem_cert_chain() ended')
        return pem_file

    def load_config(self):
        """" load config from file """
        print_debug(self.debug, 'load_config()')
        config_dic = load_config(self.debug, 'CAhandler')
        if 'api_host' in config_dic['CAhandler']:
            self.api_host = config_dic['CAhandler']['api_host']
        if 'api_user' in config_dic['CAhandler']:
            self.api_user = config_dic['CAhandler']['api_user']
        if 'api_password' in config_dic['CAhandler']:
            self.api_password = config_dic['CAhandler']['api_password']
        if 'ca_name' in config_dic['CAhandler']:
            self.ca_name = config_dic['CAhandler']['ca_name']
        print_debug(self.debug, 'CAhandler.load_config() ended')

    def set_auth(self):
        """ set basic authentication header """
        print_debug(self.debug, 'set_auth()')
        self.auth = HTTPBasicAuth(self.api_user, self.api_password)
        print_debug(self.debug, 'CAhandler.set_auth() ended')
