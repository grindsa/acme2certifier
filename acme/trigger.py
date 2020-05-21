#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Challenge class """
from __future__ import print_function
import json
from acme.helper import convert_byte_to_string
from acme.db_handler import DBstore
from acme.message import Message

class Trigger(object):
    """ Challenge handler """

    def __init__(self, debug=None, srv_name=None, logger=None, expiry=3600):
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

    def parse(self, content):
        """ new oder request """
        self.logger.debug('Trigger.parse()')
        
        # convert to json structure
        try:
            payload = json.loads(convert_byte_to_string(content))
        except:
            payload = {}    
        
        response_dic = {}
        # check message
        code = 200
        message = 'OK'
        detail = None

        # prepare/enrich response
        response_dic['header'] = {}
        response_dic['code'] = code   
        response_dic['data'] = {'status': code, 'message': message}        
        if detail:
            response_dic['data']['detail'] = detail

        self.logger.debug('challenge.parse() returns: {0}'.format(json.dumps(response_dic)))
        return response_dic

 
