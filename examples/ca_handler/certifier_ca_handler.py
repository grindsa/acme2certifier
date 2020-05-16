#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca hanlder for Insta Certifier via REST-API class """
from __future__ import print_function
import textwrap
import math
import time
import requests
from requests.auth import HTTPBasicAuth
from acme.helper import load_config, cert_serial_get, uts_now, uts_to_date_utc

class CAhandler(object):
    """ CA  handler """

    def __init__(self, debug=None, logger=None):
        self.debug = debug
        self.logger = logger
        self.api_host = None
        self.api_user = None
        self.api_password = None
        self.ca_name = None
        self.auth = None
        self.polling_timeout = 60

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
        """ enroll certificate """
        self.logger.debug('Certificate.enroll()')
        cert_bundle = None
        error = None
        cert_raw = None

        cert_dic = self.get_cert(csr)
        if cert_dic:
            if 'status' in cert_dic:
                # this is an error
                error = cert_dic['message']
            elif 'certificateBase64' in cert_dic:
                # this is a valid cert generate the bundle
                cert_bundle = self.generate_pem_cert_chain(cert_dic)
                cert_raw = cert_dic['certificateBase64']
            elif 'href' in cert_dic:
                # request is pending
                (error, cert_bundle, cert_raw) = self.poll_request(cert_dic['href'])
            else:
                error = 'no certificate information found'
        else:
            error = 'internal error'
        self.logger.debug('Certificate.enroll() ended')
        return(error, cert_bundle, cert_raw)

    def get_cert(self, csr):
        """ get certificate from CA """
        self.logger.debug('CAhandler.get_cert({0})'.format(csr))
        ca_dic = self.get_ca_properties('name', self.ca_name)
        cert_dic = {}

        if 'href' in ca_dic:
            # data = {'ca' : ca_dic['href'], 'pkcs10' : csr}
            data = {'ca' : ca_dic['href'], 'pkcs10' : csr}
            cert_dic = self.api_post(self.api_host + '/v1/requests', data)

        if not cert_dic:
            cert_dic = ca_dic

        self.logger.debug('CAhandler.enroll() ended with: {0}'.format(cert_dic))
        return cert_dic

    def get_ca(self, filter_key=None, filter_value=None):
        """ get list of CAs"""
        self.logger.debug('get_ca({0}:{1})'.format(filter_key, filter_value))
        params = {}

        if filter_key:
            params['q'] = '{0}:{1}'.format(filter_key, filter_value)
        try:
            api_response = requests.get(self.api_host + '/v1/cas', auth=self.auth, params=params, verify=False).json()
        except BaseException as err:
            api_response = {'status': 500, 'message': str(err), 'statusMessage': 'Internal Server Error'}

        self.logger.debug('CAhandler.get_ca() ended with: {0}'.format(api_response))
        return api_response

    def get_ca_properties(self, filter_key, filter_value):
        """ get properties for a single CAs"""
        self.logger.debug('get_ca_properties({0}:{1})'.format(filter_key, filter_value))
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
        self.logger.debug('CAhandler.get_ca_properties() ended with: {0}'.format(ca_dic))
        return ca_dic

    def get_cert_properties(self, serial, ca_link):
        """ get properties for a single cert """
        self.logger.debug('get_cert_properties({0}: {1})'.format(serial, ca_link))

        params = {'q' : 'issuer-id:{0},serial-number:{1}'.format(ca_link, serial)}
        try:
            api_response = requests.get(self.api_host + '/v1/certificates', auth=self.auth, params=params, verify=False).json()
        except BaseException as err:
            api_response = {'status': 500, 'message': str(err), 'statusMessage': 'Internal Server Error'}

        self.logger.debug('CAhandler.get_cert_properties() ended')
        return api_response

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
                    self.logger.debug('issuer found: {0}'.format(cert_dic['issuer']))
                    ca_cert_dic = requests.get(cert_dic['issuer'], auth=self.auth, verify=False).json()
                else:
                    self.logger.debug('issuer found: {0}'.format(cert_dic['issuerCa']))
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

        self.logger.debug('CAhandler.generate_pem_cert_chain() ended')
        return pem_file

    def load_config(self):
        """" load config from file """
        self.logger.debug('load_config()')
        config_dic = load_config(self.logger, 'CAhandler')
        if 'api_host' in config_dic['CAhandler']:
            self.api_host = config_dic['CAhandler']['api_host']
        if 'api_user' in config_dic['CAhandler']:
            self.api_user = config_dic['CAhandler']['api_user']
        if 'api_password' in config_dic['CAhandler']:
            self.api_password = config_dic['CAhandler']['api_password']
        if 'ca_name' in config_dic['CAhandler']:
            self.ca_name = config_dic['CAhandler']['ca_name']
        self.logger.debug('CAhandler.load_config() ended')

    def poll_request(self, request_url):
        """ poll request """
        self.logger.debug('CAhandler.poll_request({0})'.format(request_url))

        error = 'Polling timeout reached'
        cert_bundle = None
        cert_raw = None

        # calculate iterations based on timeout
        poll_cnt = math.ceil(self.polling_timeout/5)
        cnt = 1
        while cnt <= poll_cnt:
            request_dic = requests.get(request_url, auth=self.auth, verify=False).json()
            cnt += 1
            # check response
            if 'status' in request_dic:
                if request_dic['status'] == 'accepted':
                    if 'certificate' in request_dic:
                        cert_dic = requests.get(request_dic['certificate'], auth=self.auth, verify=False).json()
                        if 'certificateBase64' in cert_dic:
                            # this is a valid cert generate the bundle
                            error = None
                            cert_bundle = self.generate_pem_cert_chain(cert_dic)
                            cert_raw = cert_dic['certificateBase64']
                            break
                elif request_dic['status'] == 'rejected':
                    error = 'Request rejected by operator'
                    break
            # sleep
            time.sleep(5)
        self.logger.debug('CAhandler.poll_request() ended with error: {0}'.format(error))
        return(error, cert_bundle, cert_raw)

    def revoke(self, cert, rev_reason='unspecified', rev_date=uts_to_date_utc(uts_now())):
        """ revoke certificate """
        self.logger.debug('CAhandler.revoke({0}: {1})'.format(rev_reason, rev_date))
        # lookup REST-PATH of issuing CA
        ca_dic = self.get_ca_properties('name', self.ca_name)
        if 'href' in ca_dic:
            # get serial from pem file
            serial = cert_serial_get(self.logger, cert)
            if serial:
                # get certificate information via rest by search for ca+ serial
                cert_dic = self.get_cert_properties(serial, ca_dic['href'])
                if 'certificates' in cert_dic:
                    if 'href' in cert_dic['certificates'][0]:
                        # revoke the cert
                        data = {'newStatus': 'revoked', 'crlReason': rev_reason, 'invalidityDate': rev_date}
                        cert_dic = self.api_post(cert_dic['certificates'][0]['href'] + '/status', data)
                        if 'status' in cert_dic:
                            # code = cert_dic['status']
                            code = 400
                            message = 'urn:ietf:params:acme:error:alreadyRevoked'
                            detail = cert_dic['message']
                        else:
                            code = 200
                            message = None
                            detail = None
                    else:
                        code = 404
                        message = 'urn:ietf:params:acme:error:serverInternal'
                        detail = 'Cert path could not be found'
                else:
                    code = 404
                    message = 'urn:ietf:params:acme:error:serverInternal'
                    detail = 'Cert could not be found'
            else:
                code = 404
                message = 'urn:ietf:params:acme:error:serverInternal'
                detail = 'CA could not be found'
        else:
            code = 404
            message = 'urn:ietf:params:acme:error:serverInternal'
            detail = 'CA could not be found'

        return(code, message, detail)

    def set_auth(self):
        """ set basic authentication header """
        self.logger.debug('CAhandler.set_auth()')
        self.auth = HTTPBasicAuth(self.api_user, self.api_password)
        self.logger.debug('CAhandler.set_auth() ended')
