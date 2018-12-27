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

    def account_add(self, data_dic):
        """ add account in database """
        print_debug(self.debug, 'DBStore.account_add({0})'.format(data_dic))

        # we need this for compability with django
        created = False
        # check if we alredy have an entry for the key
        exists = self.account_search('modulus', data_dic['modulus'])
        self.db_open()
        if bool(exists):
            # update
            aname = exists[1]
            print_debug(self.debug, 'account exists: {0} id: {1}'.format(aname, exists[0]))
            self.cursor.execute('''UPDATE ACCOUNT SET alg = :alg, exponent = :exponent, kty = :kty, contact = :contact WHERE modulus = :modulus''', data_dic)
        else:
            # insert
            self.cursor.execute('''INSERT INTO ACCOUNT(alg, exponent, kty, modulus, contact, name) VALUES(:alg, :exponent, :kty, :modulus, :contact, :name)''', data_dic)
            aname = data_dic['name']
            created = True

        self.db_close()
        return(aname, created)

    def account_delete(self, aname):
        """ add account in database """
        print_debug(self.debug, 'DBStore.account_delete({0})'.format(aname))
        self.db_open()
        pre_statement = 'DELETE FROM account WHERE name LIKE ?'
        self.cursor.execute(pre_statement, [aname])
        result = bool(self.cursor.rowcount)
        self.db_close()
        return result

    def account_lookup(self, column, string):
        """ lookup account table for a certain key/value pair and return id"""
        print_debug(self.debug, 'DBStore.account_lookup(column:{0}, pattern:{1})'.format(column, string))
        lookup = self.account_search(column, string)
        if lookup:
            result = {'id' : lookup[0], 'name' : lookup[1]}
        else:
            result = None
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
            CREATE TABLE "account" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "alg" varchar(10) NOT NULL, "exponent" varchar(10) NOT NULL, "kty" varchar(10) NOT NULL, "modulus" varchar(1024) UNIQUE NOT NULL, "contact" varchar(15) NOT NULL, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        ''')
        print_debug(self.debug, 'create status')
        self.cursor.execute('''
            CREATE TABLE "status" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) UNIQUE NOT NULL)
        ''')
        self.cursor.execute('''INSERT INTO status(name) VALUES(:name)''', {'name': 'invalid'})
        self.cursor.execute('''INSERT INTO status(name) VALUES(:name)''', {'name': 'pending'})
        self.cursor.execute('''INSERT INTO status(name) VALUES(:name)''', {'name': 'ready'})
        self.cursor.execute('''INSERT INTO status(name) VALUES(:name)''', {'name': 'processing'})
        self.cursor.execute('''INSERT INTO status(name) VALUES(:name)''', {'name': 'valid'})
        print_debug(self.debug, 'create orders')
        self.cursor.execute('''
            CREATE TABLE "orders" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) UNIQUE NOT NULL, "notbefore" integer, "notafter" integer, "identifiers" varchar(1048) NOT NULL, "account_id" integer NOT NULL REFERENCES "acme_account" ("id"), "status_id" integer NOT NULL REFERENCES "status" ("id") DEFAULT 2, "expires" integer NOT NULL, "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        ''')
        print_debug(self.debug, 'create authorization')
        self.cursor.execute('''
            CREATE TABLE "authorization" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "order_id" integer NOT NULL REFERENCES "acme_order" ("id"), "type" varchar(5) NOT NULL, "value" varchar(64) NOT NULL, "expires" integer, "token" varchar(64), "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        ''')
        print_debug(self.debug, 'create authorization')
        self.cursor.execute('''
            CREATE TABLE "challenge" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(15) NOT NULL UNIQUE, "token" varchar(64), "authorization_id" integer NOT NULL REFERENCES "acme_authorization" ("id"), "expires" integer, "type" varchar(10) NOT NULL, "keyauthorization" varchar(128), "status_id" integer NOT NULL REFERENCES "status" ("id"), "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)
        ''')
        self.db_close()

    def db_open(self):
        """ opens db and sets cursor """
        print_debug(self.debug, 'DBStore.db_open()')
        self.dbs = sqlite3.connect(self.db_name)
        self.cursor = self.dbs.cursor()

    def jwk_load(self, aname):
        """ looad account informatino and build jwk key dictionary """
        print_debug(self.debug, 'DBStore.jwk_load({0})'.format(aname))
        account_list = self.account_search('name', aname)

        jwk_dict = {}
        if account_list:
            jwk_dict['alg'] = account_list[2]
            jwk_dict['e'] = account_list[3]
            jwk_dict['kty'] = account_list[4]
            jwk_dict['n'] = account_list[5]
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
        self.cursor.execute('''DELETE FROM nonce WHERE nonce=:nonce''', {'nonce': nonce})
        self.db_close()

    def order_add(self, data_dic):
        """ add order to database """
        print_debug(self.debug, 'DBStore.order_add({0})'.format(data_dic))
        if 'notbefore' not in data_dic:
            data_dic['notbefore'] = ''

        if 'notafter' not in data_dic:
            data_dic['notafter'] = ''

        account = self.account_lookup('name', data_dic['account'])
        if account:
            data_dic['account'] = account['id']
            self.db_open()
            self.cursor.execute('''INSERT INTO orders(name, identifiers, account_id, status_id, expires, notbefore, notafter) VALUES(:name, :identifiers, :account, :status, :expires, :notbefore, :notafter )''', data_dic)
            rid = self.cursor.lastrowid
            self.db_close()
        else:
            rid = None
        return rid

    def authorization_add(self, data_dic):
        """ add authorization to database """
        print_debug(self.debug, 'DBStore.authorization_add({0})'.format(data_dic))
        self.db_open()
        self.cursor.execute('''INSERT INTO authorization(name, order_id, type, value) VALUES(:name, :order, :type, :value)''', data_dic)
        rid = self.cursor.lastrowid
        self.db_close()
        return rid

    def authorization_update(self, data_dic):
        """ update existing authorization """
        print_debug(self.debug, 'DBStore.authorization_update({0})'.format(data_dic))
        self.db_open()
        self.cursor.execute('''UPDATE authorization SET token = :token, expires = :expires WHERE name = :name''', data_dic)
        self.cursor.execute('''SELECT id FROM authorization WHERE name=:name''', {'name': data_dic['name']})
        result = self.cursor.fetchone()[0]
        self.db_close()
        return result

    def authorization_lookup(self, column, string):
        """ search account for a given id """
        print_debug(self.debug, 'DBStore.authorization_lookup(column:{0}, pattern:{1})'.format(column, string))
        lookup = self.authorization_search(column, string)

        if lookup:
            result = {'type': lookup[3], 'value': lookup[4]}
        else:
            result = None
        return result

    def authorization_search(self, column, string):
        """ search account table for a certain key/value pair """
        print_debug(self.debug, 'DBStore.authorization_search(column:{0}, pattern:{1})'.format(column, string))
        self.db_open()
        pre_statement = 'SELECT * from authorization WHERE {0} LIKE ?'.format(column)
        self.cursor.execute(pre_statement, [string])
        result = self.cursor.fetchone()
        self.db_close()
        return result

    def challenge_add(self, data_dic):
        """ add challenge to database """
        print_debug(self.debug, 'DBStore.challenge_add({0})'.format(data_dic))
        authorization = self.authorization_search('name', data_dic['authorization'])

        if not "status" in data_dic:
            data_dic['status'] = 2
        if authorization:
            data_dic['authorization'] = authorization[0]
            self.db_open()
            self.cursor.execute('''INSERT INTO challenge(name, token, authorization_id, expires, type, status_id) VALUES(:name, :token, :authorization, :expires, :type, :status)''', data_dic)
            rid = self.cursor.lastrowid
            self.db_close()
        else:
            rid = None

        return rid

    def challenge_lookup(self, column, string):
        """ search account for a given id """
        print_debug(self.debug, 'challenge_lookup({0}:{1})'.format(column, string))
        lookup = self.challenge_search(column, string)

        if lookup:
            result = {'type' : lookup[5], 'token' : lookup[2], 'status' : lookup[10]}
        else:
            result = None
        return result

    def challenge_search(self, column, string):
        """ search challenge table for a certain key/value pair """
        print_debug(self.debug, 'DBStore.challenge_search(column:{0}, pattern:{1})'.format(column, string))
        self.db_open()
        pre_statement = 'SELECT * from challenge INNER JOIN status on status.id = challenge.status_id WHERE challenge.{0} LIKE ?'.format(column)
        self.cursor.execute(pre_statement, [string])
        result = self.cursor.fetchone()
        self.db_close()
        return result

    def challenge_update(self, data_dic):
        """ update challenge """
        print_debug(self.debug, 'challenge_update({0})'.format(data_dic))
        lookup = self.challenge_search('name', data_dic['name'])

        if 'status' not in data_dic:
            data_dic['status'] = lookup[7]
        if 'keyauthorization' not in data_dic:
            data_dic['keyauthorization'] = lookup[6]

        self.db_open()
        self.cursor.execute('''UPDATE challenge SET status_id = :status, keyauthorization = :keyauthorization WHERE name = :name''', data_dic)
        self.db_close()        
