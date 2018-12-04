#!/usr/bin/python
# -*- coding: utf-8 -*-
""" cgi handler for acmesrv.py """


class DBstore(object):
    """ helper to do datebase operations """

    @staticmethod
    def nonce_add(nonce):
        """ check if nonce is in datbase
        in: nonce
        return: rowid """
        id = 1234
        return id

    @staticmethod
    def nonce_delete(nonce):
        """ delete nonce from datbase
        in: nonce """
        foo = None

    @staticmethod
    def nonce_check(nonce):
        """ ceck if nonce is in datbase
        in: nonce
        return: true in case nonce exit, otherwise false """
        return True
