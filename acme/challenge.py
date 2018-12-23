#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Signature class """
from __future__ import print_function
from acme.helper import print_debug, generate_random_string
from acme.db_handler import DBstore

class Challenge(object):
    """ Challenge handler """

    def __init__(self, debug=None, srv_name=None, expiry=3600):
        self.debug = debug
        self.srv_name = srv_name
        self.dbstore = DBstore(self.debug)
        self.expiry = expiry
        self.path = 'acme/chall'

    def new(self, authz_name, mtype, token):
        """ new challenge """
        print_debug(self.debug, 'Challenge.new({0})'.format(mtype))

        challenge_name = generate_random_string(self.debug, 12)

        data_dic = {
            'name' : challenge_name,
            'expires' : self.expiry,
            'type' : mtype,
            'token' : token,
            'authorization' : authz_name,
        }
        chid = self.dbstore.challenge_add(data_dic)

        challenge_dic = {}
        if chid:
            challenge_dic['type'] = type
            challenge_dic['url'] = '{0}/{1}/{2}'.format(self.srv_name, self.path, challenge_name)
            challenge_dic['token'] = token

        return challenge_dic

    def new_set(self, authz_name, token):
        """ net challenge set """
        print_debug(self.debug, 'Challenge.new_set({0}, {1})'.format(authz_name, token))
        challenge_list = []
        challenge_list.append(self.new(authz_name, 'http-01', token))
        challenge_list.append(self.new(authz_name, 'dns-01', token))

        return challenge_list
