#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca hanlder for Insta Certifier via REST-API class """
from __future__ import print_function
import sys
import requests
from acme.helper import load_config, csr_cn_get, b64_url_recode

class CAhandler(object):
    """ CA  handler """

    def __init__(self, _debug=None, logger=None):
        self.logger = logger
        self.api_host = None
        self.credential_dic = {'api_user' : None, 'self.api_password' : None}
        self.tsg_info_dic = {'name' : None, 'id' : None}
        self.headers = None
        self.ca_name = None

    def __enter__(self):
        """ Makes CAhandler a Context Manager """
        if not self.api_host:
            self.load_config()

        if not self.headers:
            self.login()

        if not self.tsg_info_dic['id']:
            self.tsg_id_lookup()

        return self

    def __exit__(self, *args):
        """ cose the connection at the end of the context """

    def api_post(self, url, data):
        """  generic wrapper for an API post call """
        self.logger.debug('CAhandler.api_post()')
        try:
            api_response = requests.post(url=url, json=data, headers=self.headers, verify=False).json()
        except BaseException as err:
            api_response = err

        self.logger.debug('CAhandler.api_post() ended with: {0}'.format(api_response))
        return api_response

    def ca_id_lookup(self):
        """ lookup CA ID based on CA_name """
        self.logger.debug('CAhandler.csr_lookup()')
        # query CAs
        ca_list = requests.get(self.api_host + '/ca?freeText=' + str(self.ca_name), headers=self.headers, verify=False).json()
        ca_id = None
        if 'CAs' in ca_list:
            for ca_cert in ca_list['CAs']:
                # compare name or description field against config value
                if (ca_cert['name'] == self.ca_name or ca_cert['desc'] == self.ca_name):
                    ca_id = ca_cert['id']
        else:
            # log error
            self.logger.error('ca_id.lookup() no CAs found....')

        if not ca_id:
            # log error
            self.logger.error('ca_id_lookup(): no ca id found for {0}'.format(self.ca_name))
        self.logger.debug('CAhandler.csr_lookup() ended with: {0}'.format(ca_id))
        return ca_id

    def csr_lookup(self, csr_cn):
        """ lookup CSR based on CN """
        self.logger.debug('CAhandler.csr_lookup()')

        # get unused requests from NCLM
        request_list = self.unusedrequests_get()
        req_id = None
        # check every CSR
        for req in request_list:
            req_cn = None
            if 'subjectName' in req:
                # split the subject and filter CN
                subject_list = req['subjectName'].split(',')
                for field in subject_list:
                    field = field.strip()
                    if field.startswith('CN='):
                        req_cn = field.lower().replace('cn=', '')
                        break

            # compare csr cn with request cn
            if csr_cn:
                if req_cn == csr_cn.lower():
                    req_id = req['requestID']
                    break
            else:
                # special certbot scenario (no CN in CSR). No better idea how to handle this
                if not req_cn:
                    req_id = req['requestID']

        self.logger.debug('CAhandler.csr_lookup() ended with: {0}'.format(req_id))
        return req_id

    def enroll(self, csr):
        """ enroll certificate from NCLM """
        self.logger.debug('CAhandler.enroll()')
        cert_bundle = None
        error = None
        cert_raw = None

        # recode csr
        csr = b64_url_recode(self.logger, csr)

        if self.tsg_info_dic['id']:

            ca_id = self.ca_id_lookup()
            # get common name of CSR
            csr_cn = csr_cn_get(self.logger, csr)
            # import csr to NCLM
            result = self.request_import(csr)
            # lookup csr id
            csr_id = self.csr_lookup(csr_cn)

            if ca_id and csr_id and self.tsg_info_dic['id']:
                data_dic = {"targetSystemGroupID": self.tsg_info_dic['id'], "caID": ca_id, "requestID": csr_id}
                result = self.api_post(self.api_host + '/targetsystemgroups/' + str(self.tsg_info_dic['id']) + '/enroll/ca/' + str(ca_id), data_dic)
                print(result)
            else:
                self.logger.error('enrollment aborted. ca_id: {0}, csr_id: {1}, tsg_id: {2}'.format(ca_id, csr_id, self.tsg_info_dic['id']))

        else:
            error = 'ID lookup for targetSystemGroup "{0}" failed.'.format(self.tsg_info_dic['name'])

    def login(self):
        """ login into NCLM API """
        self.logger.debug('CAhandler.login()')
        # check first if API is reachable
        api_response = requests.get(self.api_host)
        self.logger.debug('api response code:{0}'.format(api_response.status_code))
        if api_response.ok:
            # all fine try to login
            self.logger.debug('log in to {0} as user "{1}"'.format(self.api_host, self.credential_dic['api_user']))
            data = {'username' : self.credential_dic['api_user'], 'password' : self.credential_dic['api_password']}
            api_response = requests.post(url=self.api_host + '/token?grant_type=client_credentials', json=data)
            if api_response.ok:
                json_dic = api_response.json()
                if 'access_token' in json_dic:
                    # self.token = json_dic['access_token']
                    self.headers = {"Authorization":"Bearer {0}".format(json_dic['access_token'])}
                    self.logger.debug('login response:\n user: {0}\n token: {1}\n realms: {2}\n'.format(json_dic['username'], json_dic['access_token'], json_dic['realms']))
                else:
                    self.logger.error('No token returned. Aborting....')
                    sys.exit(0)
            else:
                self.logger.error(api_response.raise_for_status())
        else:
            # If response code is not ok (200), print the resulting http error code with description
            self.logger.error(api_response.raise_for_status())
            sys.exit(0)

    def load_config(self):
        """" load config from file """
        self.logger.debug('CAhandler.load_config()')
        config_dic = load_config(self.logger, 'CAhandler')
        if 'api_host' in config_dic['CAhandler']:
            self.api_host = config_dic['CAhandler']['api_host']
        if 'api_user' in config_dic['CAhandler']:
            self.credential_dic['api_user'] = config_dic['CAhandler']['api_user']
        if 'api_password' in config_dic['CAhandler']:
            self.credential_dic['api_password'] = config_dic['CAhandler']['api_password']
        if 'ca_name' in config_dic['CAhandler']:
            self.ca_name = config_dic['CAhandler']['ca_name']

        if 'tsg_name' in config_dic['CAhandler']:
            self.tsg_info_dic['name'] = config_dic['CAhandler']['tsg_name']
        self.logger.debug('CAhandler.load_config() ended')

    def request_import(self, csr):
        """ import certificate request to NCLM """
        self.logger.debug('CAhandler.request_import()')
        data_dic = {'pkcs10' : csr}
        result = self.api_post(self.api_host + '/targetsystemgroups/' + str(self.tsg_info_dic['id']) + '/importrequest', data_dic)
        return result

    def unusedrequests_get(self):
        """ get unused requests """
        self.logger.debug('CAhandler.requests_get()')
        return requests.get(self.api_host + '/targetsystemgroups/' + str(self.tsg_info_dic['id']) + '/unusedrequests', headers=self.headers, verify=False).json()

    def tsg_id_lookup(self):
        """ get target system id based on name """
        self.logger.debug('CAhandler.tsg_id_lookup() for tsg: {0}'.format(self.tsg_info_dic['name']))
        tsg_list = requests.get(self.api_host + '/targetsystemgroups?freeText=' + str(self.tsg_info_dic['name']) + '&offset=0&limit=50&fetchPath=true', headers=self.headers, verify=False).json()
        if 'targetSystemGroups' in tsg_list:
            for tsg in tsg_list['targetSystemGroups']:
                if 'name' in tsg:
                    if self.tsg_info_dic['name'] == tsg['name']:
                        self.tsg_info_dic['id'] = tsg['id']
                        break

        else:
            self.logger.error('tsg_id_lookup() no target-system-groups found for filter: {0}....'.format(self.tsg_info_dic['name']))
        self.logger.debug('CAhandler.tsg_id_lookup() ended with: {0}'.format(str(self.tsg_info_dic['id'])))
