#!/usr/bin/python
# -*- coding: utf-8 -*-
""" django handler for acmesrv.py """
from __future__ import print_function
from acme.models import Account, Nonce
from acme.helper import print_debug

class DBstore(object):
    """ helper to do datebase operations """

    def __init__(self, debug=False):
        """ init """
        self.debug = debug

    def account_add(self, alg, exponent, kty, modulus, contact):
        """ add account in database """
        print_debug(self.debug, 'DBStore.account_add(alg:{0}, e:{1}, kty:{2}, n:{3}, contact: {4})'.format(alg, exponent, kty, modulus, contact))
        obj, created = Account.objects.update_or_create(modulus=modulus, defaults={'alg': alg, 'exponent': exponent, 'kty': kty, 'modulus': modulus, 'contact': contact})
        obj.save()
        return (obj.id, created)

    @staticmethod
    def account_lookup(mkey, value):
        """ search account for a given id """
        account_dict = Account.objects.filter(**{mkey: value}).values('id', 'alg', 'exponent', 'kty', 'modulus')[:1]
        if account_dict:
            result = account_dict[0]['id']
        else:
            result = None
        return result

    def account_delete(self, aid):
        """ add account in database """
        print_debug(self.debug, 'DBStore.account_delete({0})'.format(aid))
        result = Account.objects.filter(id=aid).delete()
        return result

    def jwk_load(self, aid):
        """ looad account informatino and build jwk key dictionary """
        print_debug(self.debug, 'DBStore.jwk_load({0})'.format(aid))
        account_dict = Account.objects.filter(id=aid).values('alg', 'exponent', 'kty', 'modulus')[:1]
        jwk_dict = {}
        if account_dict:
            jwk_dict['alg'] = account_dict[0]['alg']
            jwk_dict['kty'] = account_dict[0]['kty']
            jwk_dict['e'] = account_dict[0]['exponent']
            jwk_dict['n'] = account_dict[0]['modulus']
        return jwk_dict

    def nonce_add(self, nonce):
        """ check if nonce is in datbase
        in: nonce
        return: rowid """
        print_debug(self.debug, 'DBStore.nonce_add({0})'.format(nonce))
        obj = Nonce(nonce=nonce)
        obj.save()
        return obj.id

    def nonce_check(self, nonce):
        """ ceck if nonce is in datbase
        in: nonce
        return: true in case nonce exit, otherwise false """
        print_debug(self.debug, 'DBStore.nonce_check({0})'.format(nonce))
        nonce_list = Nonce.objects.filter(nonce=nonce).values('nonce')[:1]
        return bool(nonce_list)

    def nonce_delete(self, nonce):
        """ delete nonce from datbase
        in: nonce """
        print_debug(self.debug, 'DBStore.nonce_delete({0})'.format(nonce))
        Nonce.objects.filter(nonce=nonce).delete()
