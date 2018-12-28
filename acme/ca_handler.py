#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca hanlder for Insta Certifier via REST-API class """
from __future__ import print_function
import requests
from requests.auth import HTTPBasicAuth
from acme.helper import print_debug
import textwrap

class CAhandler(object):
    """ CA  handler """

    def __init__(self, debug=None):
        self.debug = debug
        self.api_host = 'http://192.168.14.137:8084'
        self.api_user = 'xxxxx'
        self.api_passwd = 'xxxx'
        self.auth = HTTPBasicAuth(self.api_user, self.api_passwd)

    def __enter__(self):
        """ Makes ACMEHandler a Context Manager """
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
        api_response = requests.post(url=url, json=data, auth=self.auth, verify=False)
        if api_response.ok:
            json_dic = api_response.json()
            return json_dic
        else:
            print(api_response.raise_for_status())
            return None

    def enroll(self, ca_name, csr):
        """ get key for a specific account id """
        print_debug(self.debug, 'CAhandler.enroll({0},{1})'.format(ca_name, csr))
        ca_dic = self.get_ca_properties('name', 'ncm_sub_ca')
        cert_dic = {}
        if 'href' in ca_dic:
            data = {'ca' : ca_dic['href'], 'pkcs10' : csr}
            cert_dic = self.api_post(self.api_host + '/v1/requests', data)
        return cert_dic

    def get_ca(self, filter_key=None, filter_value=None):
        """ get list of CAs"""
        print_debug(self.debug, 'get_ca({0}:{1})'.format(filter_key, filter_value))
        params = {}
        if filter_key:
            params['q'] = '{0}:{1}'.format(filter_key, filter_value)
        return requests.get(self.api_host + '/v1/cas', auth=self.auth, params=params, verify=False).json()

    def get_ca_properties(self, filter_key, filter_value):
        """ get properties for a single CAs"""
        print_debug(self.debug, 'get_ca_properties({0}:{1})'.format(filter_key, filter_value))
        ca_list = self.get_ca(filter_key, filter_value)
        ca_dic = {}
        if 'cas' in ca_list:
            for cas in ca_list['cas']:
                if cas[filter_key] == filter_value:
                    ca_dic = cas
                    break
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
            
        print(pem_file)    
 