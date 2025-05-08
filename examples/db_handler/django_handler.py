#!/usr/bin/python
# -*- coding: utf-8 -*-
"""django handler for acme2certifier"""
# pylint: disable=c0413, c0415, c0401, e0401, e1123, r0904, w0611
from __future__ import print_function
import os
import sys
import json
from typing import List, Tuple, Dict


def initialize():  # nopep8
    """initialize routine when calling dbstore functions from script"""
    sys.path.append(
        os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir))
    )
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "acme2certifier.settings")
    import django

    # pylint: disable=E1101
    django.setup()
    return django.VERSION[0]


DJANGO_VERSION = initialize()
from django.conf import settings  # nopep8
from django.db import transaction  # nopep8
from django.db.models import QuerySet  # nopep8
from acme_srv.models import (
    Account,
    Authorization,
    Cahandler,
    Certificate,
    Challenge,
    Cliaccount,
    Housekeeping,
    Nonce,
    Order,
    Status,
)  # nopep8

if DJANGO_VERSION < 4:
    import acme_srv.monkey_patches  # nopep8 lgtm [py/unused-import]


class DBstore(object):
    """helper to do datebase operations"""

    def __init__(self, _debug: bool = False, logger: object = None):
        """init"""
        self.logger = logger

    def _account_getinstance(self, aname: str) -> QuerySet:
        """get account instance"""
        self.logger.debug("DBStore._account_getinstance(%s)", aname)
        return Account.objects.get(name=aname)

    def _authorization_getinstance(self, name: str) -> QuerySet:
        """get authorization instance"""
        self.logger.debug("DBStore._authorization_getinstance(%s)", name)
        return Authorization.objects.get(name=name)

    def _modify_key(self, mkey: str, operant: str) -> str:
        """quick hack"""
        self.logger.debug("DBStore._modify_key(%s/%s)", mkey, operant)

        if operant == "<=":
            mkey = f"{mkey}__lte"

        self.logger.debug("DBStore._modify_key() ended with: %s", mkey)
        return mkey

    def _order_getinstance(self, value: str = id, mkey: id = "id") -> QuerySet:
        """get order instance"""
        self.logger.debug("DBStore._order_getinstance(%s:%s)", mkey, value)
        return Order.objects.get(**{mkey: value})

    def _status_getinstance(self, value: str, mkey: str = "id") -> QuerySet:
        """get account instance"""
        self.logger.debug("DBStore._status_getinstance(%s:%s)", mkey, value)
        return Status.objects.get(**{mkey: value})

    def account_add(self, data_dic: Dict[str, str]) -> Tuple[str, bool]:
        """add account in database"""
        self.logger.debug("DBStore.account_add(%s)", data_dic)
        account_list = self.account_lookup("jwk", data_dic["jwk"])
        if account_list:
            created = False
            aname = account_list["name"]
        else:
            obj, created = Account.objects.update_or_create(
                name=data_dic["name"], defaults=data_dic
            )
            obj.save()
            aname = data_dic["name"]
        return aname, created

    def account_lookup(
        self,
        mkey: str,
        value: str,
        vlist: List = ["id", "jwk", "name", "contact", "alg", "created_at"],
    ) -> Dict[str, str]:
        """search account for a given id"""
        self.logger.debug("DBStore.account_lookup(%s:%s)", mkey, value)
        account_dict = Account.objects.filter(**{mkey: value}).values(*vlist)[:1]
        if account_dict.exists():
            result = account_dict[0]
        else:
            result = None
        return result

    def account_delete(self, aname):
        """add account in database"""
        self.logger.debug("DBStore.account_delete(%s)", aname)
        result = Account.objects.filter(name=aname).delete()
        return result

    def account_update(self, data_dic: Dict[str, str], active: bool = True) -> int:  # NOSONAR
        """ update existing account """
        self.logger.debug('DBStore.account_update(%s)', data_dic)
        obj, _created = Account.objects.update_or_create(name=data_dic['name'], defaults=data_dic)
        obj.save()
        self.logger.debug("acct_id(%s)", obj.id)
        return obj.id

    def accountlist_get(self) -> Tuple[List[str], QuerySet]:
        """accountlist_get"""
        self.logger.debug("DBStore.accountlist_get()")
        vlist = [
            "id",
            "name",
            "contact",
            "eab_kid",
            "created_at",
            "jwk",
            "alg",
            "order__id",
            "order__name",
            "order__status__id",
            "order__status__name",
            "order__notbefore",
            "order__notafter",
            "order__expires",
            "order__identifiers",
            "order__authorization__id",
            "order__authorization__name",
            "order__authorization__type",
            "order__authorization__value",
            "order__authorization__expires",
            "order__authorization__token",
            "order__authorization__created_at",
            "order__authorization__status_id",
            "order__authorization__status__id",
            "order__authorization__status__name",
            "order__authorization__challenge__id",
            "order__authorization__challenge__name",
            "order__authorization__challenge__token",
            "order__authorization__challenge__expires",
            "order__authorization__challenge__type",
            "order__authorization__challenge__keyauthorization",
            "order__authorization__challenge__created_at",
            "order__authorization__challenge__status__id",
            "order__authorization__challenge__status__name",
        ]
        # for historical reason cert_raw an be NULL or ''; we have to consider both cases during selection
        return vlist, list(Account.objects.filter(name__isnull=False).values(*vlist))

    def authorization_add(self, data_dic: Dict[str, str]) -> int:
        """add authorization to database"""
        self.logger.debug("DBStore.authorization_add(%s)", data_dic)

        # get some instance for DB insert
        if "order" in data_dic:
            data_dic["order"] = self._order_getinstance(data_dic["order"], "id")
        if "status" in data_dic:
            data_dic["status"] = self._status_getinstance(data_dic["status"], "name")

        # add authorization
        obj, _created = Authorization.objects.update_or_create(
            name=data_dic["name"], defaults=data_dic
        )
        obj.save()
        self.logger.debug("auth_id(%s)", obj.id)
        return obj.id

    def authorization_lookup(
        self, mkey: str, value: str, vlist: List[str] = ("type", "value")
    ) -> QuerySet:
        """search account for a given id"""
        self.logger.debug("authorization_lookup(%s:%s:%s)", mkey, value, vlist)
        authz_list = Authorization.objects.filter(**{mkey: value}).values(*vlist)[::1]
        return authz_list

    def authorizations_expired_search(
        self,
        mkey: str,
        value: str,
        vlist: List[str] = (
            "id",
            "name",
            "expires",
            "identifiers",
            "created_at",
            "status__id",
            "status__name",
            "account__id",
            "account__name",
            "acccount__contact",
        ),
        operant: str = "LIKE",
    ) -> QuerySet:
        """search order table for a certain key/value pair"""
        self.logger.debug(
            "DBStore.authorizations_invalid_search(column:%s, pattern:%s)", mkey, value
        )

        mkey = self._modify_key(mkey, operant)

        self.logger.debug("DBStore.authorizations_invalid_search() ended")
        return (
            Authorization.objects.filter(**{mkey: value})
            .exclude(status__name="expired")
            .values(*vlist)
        )

    def authorization_update(self, data_dic: Dict[str, str]) -> int:
        """update existing authorization"""
        self.logger.debug("DBStore.authorization_update(%s)", data_dic)
        # get some instance for DB insert
        if "status" in data_dic:
            data_dic["status"] = self._status_getinstance(data_dic["status"], "name")

        if (
            DJANGO_VERSION < 4
            and settings.DATABASES["default"]["ENGINE"] == "django.db.backends.sqlite3"
        ):
            self.logger.debug(
                "DBStore.authorization_update(): patching transaction to transform all atomic blocks into immediate transactions"
            )
            with transaction.atomic(immediate=True):
                # update authorization
                obj, _created = Authorization.objects.update_or_create(
                    name=data_dic["name"], defaults=data_dic
                )
                obj.save()
        else:
            # update authorization
            obj, _created = Authorization.objects.update_or_create(
                name=data_dic["name"], defaults=data_dic
            )
            obj.save()

        self.logger.debug("auth_id(%s)", obj.id)
        return obj.id

    def cahandler_add(self, data_dic: Dict[str, str]) -> Tuple[str, bool]:
        """add cahandler to database"""
        self.logger.debug("DBStore.cahandler_add(%s)", data_dic)
        cahandler_list = self.cahandler_lookup("name", data_dic["name"])
        if cahandler_list:
            created = False
            cname = cahandler_list["name"]
        else:
            obj, created = Cahandler.objects.update_or_create(
                name=data_dic["name"], defaults=data_dic
            )
            obj.save()
            cname = data_dic["name"]
        return (cname, created)

    def cahandler_lookup(self, mkey: str, value: str) -> Dict[str, str]:
        """search cahandler for a given id"""
        self.logger.debug("DBStore.cahandler_lookup(%s:%s)", mkey, value)
        cahandler_dict = Cahandler.objects.filter(**{mkey: value}).values(
            "name", "value1", "value2", "created_at"
        )[:1]
        if cahandler_dict.exists():
            result = cahandler_dict[0]
        else:
            result = None
        return result

    def challenge_add(self, value: str, mtype: str, data_dic: Dict[str, str]) -> int:
        """add challenge to database"""
        self.logger.debug("DBStore.challenge_add(%s:%s)", value, mtype)

        # get order instance for DB insert
        data_dic["authorization"] = self._authorization_getinstance(
            data_dic["authorization"]
        )

        # replace orderstatus with an instance
        data_dic["status"] = self._status_getinstance(data_dic["status"])

        if (
            DJANGO_VERSION < 4
            and settings.DATABASES["default"]["ENGINE"] == "django.db.backends.sqlite3"
        ):
            self.logger.debug(
                "DBStore.challenge_add(): patching transaction to transform all atomic blocks into immediate transactions"
            )
            with transaction.atomic(immediate=True):
                obj, _created = Challenge.objects.update_or_create(
                    name=data_dic["name"], defaults=data_dic
                )
                obj.save()
        else:
            obj, _created = Challenge.objects.update_or_create(
                name=data_dic["name"], defaults=data_dic
            )
            obj.save()

        self.logger.debug("cid(%s)", obj.id)
        self.logger.debug("DBStore.challenge_add(%s:%s:%s)", value, mtype, obj.id)
        return obj.id

    def certificate_add(self, data_dic: Dict[str, str]) -> int:
        """add csr/certificate to database"""
        self.logger.debug("DBStore.certificate_add()")

        # get order instance for DB insert
        if "order" in data_dic:
            data_dic["order"] = self._order_getinstance(data_dic["order"], "name")
        # add certificate/CSR
        obj, _created = Certificate.objects.update_or_create(
            name=data_dic["name"], defaults=data_dic
        )
        obj.save()
        self.logger.debug("DBStore.certificate_add() ended with :%s", obj.id)
        return obj.id

    def certificate_account_check(self, account_name: str, certificate: str) -> str:
        """check issuer against certificate"""
        self.logger.debug("DBStore.certificate_account_check(%s)", account_name)

        result = None
        certificate_list = self.certificate_lookup(
            "cert_raw", certificate, ["name", "order__name", "order__account__name"]
        )

        if certificate_list:
            if account_name:
                # if there is an acoount name validate it against the account_name from db-query
                if account_name == certificate_list["order__account__name"]:
                    result = certificate_list["order"]
            else:
                # no account name given (message signed with domain key
                result = certificate_list["order"]

        self.logger.debug("DBStore.certificate_account_check() ended with: %s", result)
        return result

    def certificate_delete(self, mkey: str, value: str) -> QuerySet:
        """delete certificate from table"""
        self.logger.debug("DBStore.certificate_delete(%s:%s)", mkey, value)
        Certificate.objects.filter(**{mkey: value}).delete()

    def certificatelist_get(self) -> Tuple[List[str], List[QuerySet]]:
        """certificatelist_get"""
        self.logger.debug("DBStore.certificatelist_get()")
        vlist = [
            "id",
            "name",
            "cert_raw",
            "csr",
            "poll_identifier",
            "created_at",
            "issue_uts",
            "expire_uts",
            "order__id",
            "order__name",
            "order__status__name",
            "order__notbefore",
            "order__notafter",
            "order__expires",
            "order__identifiers",
            "order__account__name",
            "order__account__contact",
            "order__account__created_at",
            "order__account__jwk",
            "order__account__alg",
            "order__account__eab_kid",
        ]
        # for historical reason cert_raw an be NULL or ''; we have to consider both cases during selection
        return (
            vlist,
            list(
                Certificate.objects.filter(cert_raw__isnull=False)
                .exclude(cert_raw="")
                .values(*vlist)
            ),
        )

    def certificate_lookup(
        self,
        mkey: str,
        value: str,
        vlist: List[str] = ("name", "csr", "cert", "order__name"),
    ) -> Dict[str, str]:
        """search certificate based on "something" """
        self.logger.debug("DBStore.certificate_lookup(%s:%s)", mkey, value)
        certificate_list = Certificate.objects.filter(**{mkey: value}).values(*vlist)[
            :1
        ]
        if certificate_list:
            result = certificate_list[0]
            if "order__name" in result:
                result["order"] = result["order__name"]
                del result["order__name"]
        else:
            result = None
        self.logger.debug("DBStore.certificate_lookup() ended with: %s", result)
        return result

    def certificates_search(
        self,
        mkey: str,
        value: str,
        vlist: List[str] = ("name", "csr", "cert", "order__name"),
        operant=None,
    ) -> QuerySet:
        """search certificate based on "something" """
        self.logger.debug("DBStore.certificates_search(%s:%s)", mkey, value)
        mkey = self._modify_key(mkey, operant)
        return Certificate.objects.filter(**{mkey: value}).values(*vlist)

    def challenge_lookup(
        self,
        mkey: str,
        value: str,
        vlist: List[str] = ("type", "token", "status__name"),
    ) -> Dict[str, str]:
        """search account for a given id"""
        self.logger.debug("DBStore.challenge_lookup(%s:%s)", mkey, value)
        challenge_list = Challenge.objects.filter(**{mkey: value}).values(*vlist)[:1]
        if challenge_list:
            result = challenge_list[0]
            if "status__name" in result:
                result["status"] = result["status__name"]
                del result["status__name"]
            if "authorization__name" in result:
                result["authorization"] = result["authorization__name"]
                del result["authorization__name"]
        else:
            result = None
        return result

    def challenges_search(
        self,
        mkey: str,
        value: str,
        vlist: List[str] = ("name", "type", "cert", "status__name", "token"),
    ) -> QuerySet:
        """search challenges based on "something" """
        self.logger.debug("DBStore.challenges_search(%s:%s)", mkey, value)
        return Challenge.objects.filter(**{mkey: value}).values(*vlist)

    def challenge_update(self, data_dic: Dict[str, str]):
        """update challenge"""
        self.logger.debug("challenge_update(%s)", data_dic)
        # replace orderstatus with an instance
        if "status" in data_dic:
            data_dic["status"] = self._status_getinstance(data_dic["status"], "name")
        obj, _created = Challenge.objects.update_or_create(
            name=data_dic["name"], defaults=data_dic
        )
        obj.save()

    def cli_jwk_load(self, aname: str) -> Dict[str, str]:
        """looad account informatino and build jwk key dictionary from cliaccounts teable"""
        self.logger.debug("DBStore.cli_jwk_load(%s)", aname)
        account_dict = Cliaccount.objects.filter(name=aname).values("jwk")[:1]
        jwk_dict = {}
        if account_dict:
            try:
                jwk_dict = json.loads(account_dict[0]["jwk"].decode())
            except Exception as _err:
                self.logger.error("DBStore.cli_jwk_load(): error: %s", _err)
                jwk_dict = json.loads(account_dict[0]["jwk"])
        return jwk_dict

    def cli_permissions_get(self, aname: str) -> Dict[str, str]:
        """looad account informations and build jwk key dictionary from cliaccounts teable"""
        self.logger.debug("DBStore.cli_jwk_load(%s)", aname)
        account_dict = Cliaccount.objects.filter(name=aname).values(
            "reportadmin", "cliadmin", "certificateadmin"
        )[:1]
        permissions_dict = {}
        if account_dict.exists():
            permissions_dict = account_dict[0]
        return permissions_dict

    def dbversion_get(self) -> Tuple[Dict[str, str], str]:
        """get db version from housekeeping table"""
        self.logger.debug("DBStore.dbversion_get()")
        version_list = Housekeeping.objects.filter(name="dbversion").values_list(
            "value", flat=True
        )
        if version_list:
            result = version_list[0]
        else:
            result = None
        self.logger.debug("DBStore.dbversion_get() ended with %s", result)
        return (result, "tools/django_update.py")

    def hkparameter_add(self, data_dic: Dict[str, str]):
        """add housekeeping paramter to database"""
        self.logger.debug("DBStore.hkparameter_add(%s)", data_dic)
        obj, _created = Housekeeping.objects.update_or_create(
            name=data_dic["name"], defaults=data_dic
        )
        obj.save()

    def hkparameter_get(self, parameter: str) -> str:
        """get parameter from housekeeping table"""
        self.logger.debug("DBStore.hkparameter_get()")
        result_list = Housekeeping.objects.filter(name=parameter).values_list(
            "value", flat=True
        )
        if result_list:
            result = result_list[0]
        else:
            result = None
        self.logger.debug("DBStore.hkparameter_get() ended with %s", result)
        return result

    def jwk_load(self, aname: str) -> Dict[str, str]:
        """looad account informatino and build jwk key dictionary"""
        self.logger.debug("DBStore.jwk_load(%s)", aname)
        account_dict = Account.objects.filter(name=aname, status_id=5).values(
            "jwk", "alg"
        )[:1]
        jwk_dict = {}
        if account_dict:
            try:
                jwk_dict = json.loads(account_dict[0]["jwk"].decode())
            except Exception:
                jwk_dict = json.loads(account_dict[0]["jwk"])
            jwk_dict["alg"] = account_dict[0]["alg"]
        return jwk_dict

    def nonce_add(self, nonce: str) -> int:
        """check if nonce is in datbase
        in: nonce
        return: rowid"""
        self.logger.debug("DBStore.nonce_add(%s)", nonce)
        obj = Nonce(nonce=nonce)
        obj.save()
        return obj.id

    def nonce_check(self, nonce: str) -> bool:
        """ceck if nonce is in datbase
        in: nonce
        return: true in case nonce exit, otherwise false"""
        self.logger.debug("DBStore.nonce_check(%s)", nonce)
        nonce_list = Nonce.objects.filter(nonce=nonce).values("nonce")[:1]
        return bool(nonce_list)

    def nonce_delete(self, nonce: str):
        """delete nonce from datbase
        in: nonce"""
        self.logger.debug("DBStore.nonce_delete(%s)", nonce)
        Nonce.objects.filter(nonce=nonce).delete()

    def order_add(self, data_dic: Dict[str, str]) -> int:
        """add order to database"""
        self.logger.debug("DBStore.order_add(%s)", data_dic)
        # replace accountid with instance
        data_dic["account"] = self._account_getinstance(data_dic["account"])

        # replace orderstatus with an instance
        data_dic["status"] = self._status_getinstance(data_dic["status"], "id")
        obj, _created = Order.objects.update_or_create(
            name=data_dic["name"], defaults=data_dic
        )
        obj.save()
        self.logger.debug("order_id(%s)", obj.id)
        return obj.id

    def order_lookup(
        self,
        mkey: str,
        value: str,
        vlist: List[str] = (
            "name",
            "notbefore",
            "notafter",
            "identifiers",
            "status__name",
            "account__name",
            "expires",
        ),
    ) -> Dict[str, str]:
        """search orders for a given ordername"""
        self.logger.debug("order_lookup(%s:%s)", mkey, value)
        order_list = Order.objects.filter(**{mkey: value}).values(*vlist)[:1]
        if order_list:
            result = order_list[0]
            if "status__name" in result:
                result["status"] = result["status__name"]
                del result["status__name"]
            if "account_name" in result:
                result["account"] = result["account__name"]
                del result["account__name"]
        else:
            result = None
        return result

    def order_update(self, data_dic: Dict[str, str]):
        """update order"""
        self.logger.debug("order_update(%s)", data_dic)
        # replace orderstatus with an instance
        if "status" in data_dic:
            data_dic["status"] = self._status_getinstance(data_dic["status"], "name")
        obj, _created = Order.objects.update_or_create(
            name=data_dic["name"], defaults=data_dic
        )
        obj.save()

    def orders_invalid_search(
        self,
        mkey: str,
        value: str,
        vlist: List[str] = (
            "id",
            "name",
            "expires",
            "identifiers",
            "created_at",
            "status__id",
            "status__name",
            "account__id",
            "account__name",
            "acccount__contact",
        ),
        operant="LIKE",
    ) -> QuerySet:
        """search order table for a certain key/value pair"""
        self.logger.debug("DBStore.orders_search(column:%s, pattern:%s)", mkey, value)
        mkey = self._modify_key(mkey, operant)
        return Order.objects.filter(**{mkey: value}, status__id__gt=1).values(*vlist)
