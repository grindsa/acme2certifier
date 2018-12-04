#!/usr/bin/python
# -*- coding: utf-8 -*-
""" django handler for acmesrv.py """
from acme.models import Nonce

class DBstore(object):
    """ helper to do datebase operations """

    @staticmethod
    def nonce_add(nonce):
        """ check if nonce is in datbase
        in: nonce
        return: rowid """
        obj = Nonce(nonce=nonce)
        obj.save()
        return obj.id

    @staticmethod
    def nonce_delete(nonce):
        """ delete nonce from datbase
        in: nonce """
        Nonce.objects.filter(nonce=nonce).delete()

    @staticmethod
    def nonce_check(nonce):
        """ ceck if nonce is in datbase
        in: nonce
        return: true in case nonce exit, otherwise false """
        nonce_list = Nonce.objects.filter(nonce=nonce).values('nonce')[:1]
        return bool(nonce_list)
