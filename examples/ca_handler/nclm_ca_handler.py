#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ca hanlder for Insta Certifier via REST-API class """
from __future__ import print_function
import sys
import requests
from acme.helper import load_config

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
        try:
            api_response = requests.post(url=url, json=data, auth=self.auth, verify=False).json()
        except BaseException as err:
            api_response = err

        return api_response

    def enroll(self, csr):
        """ enroll certificate from NCLM """
        self.logger.debug('CAhandler.enroll()')

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
                    self.logger.debug('No token returned. Aborting....')
                    sys.exit(0)
            else:
                self.logger.debug(api_response.raise_for_status())
        else:
            # If response code is not ok (200), print the resulting http error code with description
            api_response.raise_for_status()
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

    def tsg_id_lookup(self):
        """ get target system id based on name """
        self.logger.debug('CAhandler.tsg_id_lookup() for tsg: {0}'.format(self.tsg_info_dic['name']))
        # GET /targetsystemgroups?freeText=acme&offset=0&limit=50&fetchPath=true
        tsg_list = requests.get(self.api_host + '/targetsystemgroups?freeText=' + str(self.tsg_info_dic['name']) + '&offset=0&limit=50&fetchPath=true', headers=self.headers, verify=False).json()
        if 'targetSystemGroups' in tsg_list:
            for tsg in tsg_list['targetSystemGroups']:
                if 'name' in tsg:
                    if self.tsg_info_dic['name'] == tsg['name']:
                        self.tsg_info_dic['id'] = tsg['id']
                        break
        self.logger.debug('CAhandler.tsg_id_lookup() ended with: {0}'.format(str(self.tsg_info_dic['id'])))
