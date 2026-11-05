# -*- coding: utf-8 -*-
"""ThreadWithReturnValue class"""

# pylint: disable=r0913
from threading import Thread
from typing import Any, Optional


class ThreadWithReturnValue(Thread):
    """main class"""

    def __init__(
        self, group=None, target=None, name=None, args=(), kwargs=None, *, daemon=None
    ):
        Thread.__init__(self, group, target, name, args, kwargs, daemon=daemon)

        self._return = None
        self._exception: Optional[Exception] = None

    def run(self):
        if self._target is not None:
            try:
                self._return = self._target(*self._args, **self._kwargs)
            except Exception as err:
                self._exception = err

    def join(self, timeout: int = None) -> Any:
        Thread.join(self, timeout=timeout)
        if self._exception is not None:
            raise self._exception
        return self._return
