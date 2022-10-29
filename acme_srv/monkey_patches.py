#!/usr/bin/python
# -*- coding: utf-8 -*-
""" Monkey patches class """
# pylint: disable=c0413, c0415, e0401, e1121
from django.db import DEFAULT_DB_ALIAS
from django.db import transaction
import django


def django_sqlite_atomic():
    """ monkey patch for django deployments fixing database lock issues """

    def atomic(using=None, savepoint=True, immediate=False):
        # Bare decorator: @atomic -- although the first argument is called
        # `using`, it's actually the function being decorated.
        if callable(using):
            if django.VERSION[0] < 3:
                atomic_ = transaction.Atomic(DEFAULT_DB_ALIAS, savepoint)(using)
            else:
                atomic_ = transaction.Atomic(DEFAULT_DB_ALIAS, savepoint, True)(using)
        # Decorator: @atomic(...) or context manager: with atomic(...): ...
        else:
            if django.VERSION[0] < 3:
                atomic_ = transaction.Atomic(using, savepoint)
            else:
                atomic_ = transaction.Atomic(using, savepoint, True)

        atomic_.immediate = immediate
        return atomic_

    def __enter__(self):
        """ enter function """
        connection = transaction.get_connection(self.using)
        if not connection.in_atomic_block:
            # Reset state when entering an outermost atomic block.
            connection.commit_on_exit = True
            connection.needs_rollback = False
            if not connection.get_autocommit():
                # Pretend we're already in an atomic block to bypass the code
                # that disables autocommit to enter a transaction, and make a
                # note to deal with this case in __exit__.
                connection.in_atomic_block = True
                connection.commit_on_exit = False

        if connection.in_atomic_block:
            # We're already in a transaction; create a savepoint, unless we
            # were told not to or we're already waiting for a rollback. The
            # second condition avoids creating useless savepoints and prevents
            # overwriting needs_rollback until the rollback is performed.
            if self.savepoint and not connection.needs_rollback:
                sid = connection.savepoint()
                connection.savepoint_ids.append(sid)
            else:
                connection.savepoint_ids.append(None)
        else:
            if self.immediate:
                connection.set_autocommit(False)
                connection.cursor().execute('BEGIN IMMEDIATE')

            else:
                connection.set_autocommit(False, force_begin_transaction_with_broken_autocommit=True)

            connection.in_atomic_block = True

    transaction.atomic = atomic
    transaction.Atomic.immediate = False
    transaction.Atomic.__enter__ = __enter__


django_sqlite_atomic()
