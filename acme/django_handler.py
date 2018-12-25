#!/usr/bin/python
# -*- coding: utf-8 -*-
""" django handler for acmesrv.py """
from __future__ import print_function
from acme.models import Account, Authorization, Challenge, Nonce, Order, Orderstatus
from acme.helper import print_debug

class DBstore(object):
    """ helper to do datebase operations """

    def __init__(self, debug=False):
        """ init """
        self.debug = debug

    def account_add(self, data_dic):
        """ add account in database """
        print_debug(self.debug, 'DBStore.account_add({0})'.format(data_dic))
        account_list = self.account_lookup('modulus', data_dic['modulus'])
        if account_list:
            created = False
            aname = account_list['name']
        else:
            obj, created = Account.objects.update_or_create(name=data_dic['name'], defaults=data_dic)
            obj.save()
            aname = data_dic['name']
        return (aname, created)

    # django specific
    def account_getinstance(self, aname):
        """ get account instance """
        print_debug(self.debug, 'DBStore.account_getinstance({0})'.format(aname))
        return Account.objects.get(name=aname)

    def account_lookup(self, mkey, value):
        """ search account for a given id """
        print_debug(self.debug, 'DBStore.account_lookup({0},{1})'.format(mkey, value))
        account_dict = Account.objects.filter(**{mkey: value}).values('id', 'alg', 'exponent', 'kty', 'modulus', 'name')[:1]
        if account_dict:
            result = account_dict[0]
        else:
            result = None
        return result

    def account_delete(self, aname):
        """ add account in database """
        print_debug(self.debug, 'DBStore.account_delete({0})'.format(aname))
        result = Account.objects.filter(name=aname).delete()
        return result

    def jwk_load(self, aname):
        """ looad account informatino and build jwk key dictionary """
        print_debug(self.debug, 'DBStore.jwk_load({0})'.format(aname))
        account_dict = Account.objects.filter(name=aname).values('alg', 'exponent', 'kty', 'modulus')[:1]
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

    def order_add(self, data_dic):
        """ add order to database """
        print_debug(self.debug, 'DBStore.order_add({0})'.format(data_dic))
        # replace accountid with instance
        data_dic['account'] = self.account_getinstance(data_dic['account'])

        # replace orderstatus with an instance
        data_dic['status'] = self.orderstatus_getinstance(data_dic['status'])
        obj, _created = Order.objects.update_or_create(name=data_dic['name'], defaults=data_dic)
        obj.save()
        print_debug(self.debug, 'order_id({0})'.format(obj.id))
        return obj.id

    # django specific
    def order_getinstance(self, oid):
        """ get account instance """
        print_debug(self.debug, 'DBStore.oder_getinstance({0})'.format(oid))
        return Order.objects.get(id=oid)

    # django specific
    def orderstatus_getinstance(self, oid):
        """ get account instance """
        print_debug(self.debug, 'DBStore.orderstatus_getinstance({0})'.format(oid))
        return Orderstatus.objects.get(id=oid)

    def authorization_add(self, data_dic):
        """ add authorization to database """
        print_debug(self.debug, 'DBStore.authorization_add({0})'.format(data_dic))

        # get order instance for DB insert
        data_dic['order'] = self.order_getinstance(data_dic['order'])

        # add authorization
        obj, _created = Authorization.objects.update_or_create(name=data_dic['name'], defaults=data_dic)
        obj.save()
        print_debug(self.debug, 'auth_id({0})'.format(obj.id))
        return obj.id

    def authorization_update(self, data_dic):
        """ update existing authorization """
        print_debug(self.debug, 'DBStore.authorization_update({0})'.format(data_dic))

        # add authorization
        obj, _created = Authorization.objects.update_or_create(name=data_dic['name'], defaults=data_dic)
        obj.save()

        print_debug(self.debug, 'auth_id({0})'.format(obj.id))
        return obj.id

    @staticmethod
    def authorization_lookup(mkey, value):
        """ search account for a given id """
        authz_list = Authorization.objects.filter(**{mkey: value}).values('type', 'value')[:1]
        if authz_list:
            result = authz_list[0]
        else:
            result = None

        return result

    # django specific
    def authorization_getinstance(self, name):
        """ get authorization instance """
        print_debug(self.debug, 'DBStore.authorization_getinstance({0})'.format(name))
        return Authorization.objects.get(name=name)

    def challenge_add(self, data_dic):
        """ add challenge to database """
        print_debug(self.debug, 'DBStore.challenge_add({0})'.format(data_dic))

        # get order instance for DB insert
        data_dic['authorization'] = self.authorization_getinstance(data_dic['authorization'])

        # add authorization
        obj, _created = Challenge.objects.update_or_create(name=data_dic['name'], defaults=data_dic)
        obj.save()
        print_debug(self.debug, 'cid({0})'.format(obj.id))
        return obj.id
