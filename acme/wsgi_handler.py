#!/usr/bin/python
# -*- coding: utf-8 -*-
""" cgi handler for acmesrv.py """
from __future__ import print_function
import sqlite3
import os
from acme.helper import print_debug

class DBstore(object):
    """ helper to do datebase operations """

    def __init__(self, debug=False, db_name=os.path.dirname(__file__)+'/'+'acme_srv.db'):
        """ init """
        self.db_name = db_name
        self.debug = debug
        self.dbs = None
        self.cursor = None

        if not os.path.exists(self.db_name):
            self.db_create()

    def account_add(self, alg, exponent, kty, modulus, contact):
        """ add account in database """
        print_debug(self.debug, 'DBStore.account_add(alg:{0}, e:{1}, kty:{2}, n:{3}, contact: {4})'.format(alg, exponent, kty, modulus, contact))

        # we need this for compability with django
        created = False

        # check if we alredy have an entry for the key
        exists = self.account_search('modulus', modulus)
        self.db_open()
        if bool(exists):
            # update
            rid = exists[0]
            print_debug(self.debug, 'account exists: {0} id: {1}'.format(modulus, rid))
            self.cursor.execute('''UPDATE ACCOUNT SET alg = :alg, exponent = :exponent, kty = :kty, contact = :contact WHERE modulus = :modulus''', {'alg': alg, 'modulus': modulus, 'exponent': exponent, 'kty': kty, 'contact': contact})
        else:
            # insert
            self.cursor.execute('''INSERT INTO ACCOUNT(alg, exponent, kty, modulus, contact) VALUES(:alg, :exponent, :kty, :modulus, :contact)''', {'alg': alg, 'exponent': exponent, 'kty': kty, 'modulus': modulus, 'contact': contact})
            rid = self.cursor.lastrowid
            created = True

        self.db_close()
        return (rid, created)

    def account_delete(self, aid):
        """ add account in database """
        print_debug(self.debug, 'DBStore.account_delete({0})'.format(aid))
        self.db_open()
        pre_statement = 'DELETE FROM account WHERE id LIKE ?'
        self.cursor.execute(pre_statement, [aid])
        result = bool(self.cursor.rowcount)
        self.db_close()
        return result

    def account_search(self, column, string):
        """ search account table for a certain key/value pair """
        print_debug(self.debug, 'DBStore.account_search(column:{0}, pattern:{1})'.format(column, string))
        self.db_open()
        pre_statement = 'SELECT * from account WHERE {0} LIKE ?'.format(column)
        self.cursor.execute(pre_statement, [string])
        result = self.cursor.fetchone()
        self.db_close()
        return result

    def db_close(self):
        """ commit and close """
        print_debug(self.debug, 'DBStore.db_close()')
        self.dbs.commit()
        self.dbs.close()

    def db_create(self):
        """ create the database if dos not exist """
        print_debug(self.debug, 'DBStore.db_create({0})'.format(self.db_name))
        self.db_open()
        # create nonce table
        print_debug(self.debug, 'create nonce')
        self.cursor.execute('''
            CREATE TABLE "nonce" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "nonce" varchar(30) NOT NULL, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        ''')
        print_debug(self.debug, 'create account')
        self.cursor.execute('''
            CREATE TABLE "account" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "alg" varchar(10) NOT NULL, "exponent" varchar(10) NOT NULL, "kty" varchar(10) NOT NULL, "modulus" varchar(1024) UNIQUE NOT NULL, "contact" varchar(15) NOT NULL, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        ''')
        self.db_close()

    def db_open(self):
        """ opens db and sets cursor """
        print_debug(self.debug, 'DBStore.db_open()')
        self.dbs = sqlite3.connect(self.db_name)
        self.cursor = self.dbs.cursor()

    def jwk_load(self, aid):
        """ looad account informatino and build jwk key dictionary """
        print_debug(self.debug, 'DBStore.jwk_load({0})'.format(aid))
        account_list = self.account_search('id', aid)

        # account_dict = Account.objects.filter(id=aid).values('alg', 'exponent', 'kty', 'modulus')[:1]
        jwk_dict = {}
        if account_list:
            jwk_dict['alg'] = account_list[1]
            jwk_dict['e'] = account_list[2]
            jwk_dict['kty'] = account_list[3]
            jwk_dict['n'] = account_list[4]
        return jwk_dict

    def nonce_add(self, nonce):
        """ check if nonce is in datbase
        in: nonce
        return: rowid """
        print_debug(self.debug, 'DBStore.nonce_add({0})'.format(nonce))
        self.db_open()
        self.cursor.execute('''INSERT INTO nonce(nonce) VALUES(:nonce)''', {'nonce': nonce})
        rid = self.cursor.lastrowid
        self.db_close()
        return rid

    def nonce_check(self, nonce):
        """ ceck if nonce is in datbase
        in: nonce
        return: true in case nonce exit, otherwise false """
        print_debug(self.debug, 'DBStore.nonce_check({0})'.format(nonce))
        self.db_open()
        self.cursor.execute('''SELECT nonce FROM nonce WHERE nonce=:nonce''', {'nonce': nonce})
        result = bool(self.cursor.fetchone())
        self.db_close()
        return result

    def nonce_delete(self, nonce):
        """ delete nonce from datbase
        in: nonce """
        print_debug(self.debug, 'DBStore.nonce_delete({0})'.format(nonce))
        self.db_open()
        self.cursor.execute('''delete FROM nonce WHERE nonce=:nonce''', {'nonce': nonce})
        self.db_close()
