#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for monkey_patches.py"""

import importlib
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


class _FakeAtomic:
    """Stand-in for django.db.transaction.Atomic."""

    immediate = False

    def __init__(self, using, savepoint, durable=True):
        self.using = using
        self.savepoint = savepoint
        self.durable = durable

    def __call__(self, func):
        return func


class TestMonkeyPatches(unittest.TestCase):
    """test django_sqlite_atomic monkey patch branches"""

    def setUp(self):
        self.transaction = types.SimpleNamespace(
            Atomic=_FakeAtomic,
            get_connection=MagicMock(),
            atomic=None,
        )
        self.django_db = types.SimpleNamespace(
            DEFAULT_DB_ALIAS="default",
            transaction=self.transaction,
        )
        self._modules = {
            "django": MagicMock(),
            "django.db": self.django_db,
            "django.db.transaction": self.transaction,
        }
        self._patcher = patch.dict(sys.modules, self._modules)
        self._patcher.start()
        sys.modules.pop("acme2certifier.acme_srv.monkey_patches", None)
        self.mod = importlib.import_module("acme2certifier.acme_srv.monkey_patches")

    def tearDown(self):
        sys.modules.pop("acme2certifier.acme_srv.monkey_patches", None)
        self._patcher.stop()

    def test_001_django_sqlite_atomic_decorator_and_context(self):
        """atomic() supports bare decorator and parameterized forms"""

        def target():
            return "ok"

        wrapped = self.transaction.atomic(target)
        self.assertIs(wrapped, target)
        self.assertFalse(getattr(wrapped, "immediate"))

        ctx = self.transaction.atomic(using="other", savepoint=False, immediate=True)
        self.assertIsInstance(ctx, _FakeAtomic)
        self.assertEqual(ctx.using, "other")
        self.assertFalse(ctx.savepoint)
        self.assertTrue(ctx.immediate)

        self.mod.django_sqlite_atomic()
        self.assertFalse(_FakeAtomic.immediate)

    def test_002_enter_outermost_nested_and_immediate(self):
        """Atomic.__enter__ covers outermost, nested savepoint, and immediate"""
        enter = _FakeAtomic.__enter__

        connection = MagicMock()
        connection.in_atomic_block = False
        connection.get_autocommit.return_value = True
        connection.savepoint_ids = []
        self.transaction.get_connection.return_value = connection

        self_obj = _FakeAtomic("default", True)
        self_obj.immediate = False
        enter(self_obj)
        connection.set_autocommit.assert_called()
        self.assertTrue(connection.in_atomic_block)

        connection.in_atomic_block = True
        connection.needs_rollback = False
        connection.savepoint.return_value = "sid1"
        connection.savepoint_ids = []
        enter(self_obj)
        self.assertEqual(connection.savepoint_ids, ["sid1"])

        connection.savepoint_ids = []
        self_obj.savepoint = False
        enter(self_obj)
        self.assertEqual(connection.savepoint_ids, [None])

        connection.savepoint_ids = []
        self_obj.savepoint = True
        connection.needs_rollback = True
        enter(self_obj)
        self.assertEqual(connection.savepoint_ids, [None])

        connection.in_atomic_block = False
        connection.get_autocommit.return_value = True
        self_obj.immediate = True
        cursor = MagicMock()
        connection.cursor.return_value = cursor
        enter(self_obj)
        cursor.execute.assert_called_with("BEGIN IMMEDIATE")

    def test_003_enter_pretend_atomic_when_autocommit_off(self):
        """Outer enter pretends atomic when autocommit is already off"""
        enter = _FakeAtomic.__enter__

        connection = MagicMock()
        connection.in_atomic_block = False
        connection.get_autocommit.return_value = False
        connection.needs_rollback = False
        connection.savepoint_ids = []
        connection.savepoint.return_value = "sid2"
        self.transaction.get_connection.return_value = connection

        self_obj = _FakeAtomic("default", True)
        self_obj.immediate = False
        enter(self_obj)
        self.assertFalse(connection.commit_on_exit)
        self.assertEqual(connection.savepoint_ids, ["sid2"])


if __name__ == "__main__":
    unittest.main()
