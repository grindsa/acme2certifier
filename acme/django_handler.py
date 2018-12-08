#!/usr/bin/python
# -*- coding: utf-8 -*-
""" django handler for acmesrv.py """
from __future__ import print_function
from datetime import datetime
from acme.models import Account, Nonce

def print_debug(debug, text):
    """ little helper to print debug messages
        args:
            debug = debug flag
            text  = text to print
        returns:
            (text)
    """
    if debug:
        print('{0}: {1}'.format(datetime.now(), text))

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
