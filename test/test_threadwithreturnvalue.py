#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for threadwithreturnvalue.py"""

import unittest

from acme2certifier.acme_srv.threadwithreturnvalue import ThreadWithReturnValue


class TestThreadWithReturnValue(unittest.TestCase):
    """test ThreadWithReturnValue"""

    def test_001_join_returns_target_result(self):
        """join() returns the value produced by the target"""

        def _target(value: int) -> int:
            return value * 2

        thread = ThreadWithReturnValue(target=_target, args=(21,))
        thread.start()
        self.assertEqual(thread.join(), 42)

    def test_002_join_returns_none_without_target(self):
        """join() returns None when no target was set"""
        thread = ThreadWithReturnValue()
        thread.start()
        self.assertIsNone(thread.join())

    def test_003_join_passes_kwargs_to_target(self):
        """target receives kwargs and join returns its result"""

        def _target(a: int, b: int = 0) -> int:
            return a + b

        thread = ThreadWithReturnValue(target=_target, args=(3,), kwargs={"b": 4})
        thread.start()
        self.assertEqual(thread.join(), 7)


if __name__ == "__main__":
    unittest.main()
