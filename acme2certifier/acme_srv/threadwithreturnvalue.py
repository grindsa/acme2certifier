# -*- coding: utf-8 -*-
"""ThreadWithReturnValue class"""

# pylint: disable=r0913
from threading import Thread

from acme2certifier.acme_srv.helpers.otel import context_attach, context_capture


class ThreadWithReturnValue(Thread):
    """main class"""

    def __init__(
        self, group=None, target=None, name=None, args=(), kwargs=None, *, daemon=None
    ):
        Thread.__init__(self, group, target, name, args, kwargs, daemon=daemon)

        self._return = None
        # Propagate OTEL context so child spans nest under the HTTP root span.
        self._otel_context = context_capture()

    def run(self):
        with context_attach(self._otel_context):
            if self._target is not None:
                self._return = self._target(*self._args, **self._kwargs)

    def join(self, timeout: int = None):
        Thread.join(self, timeout=timeout)
        return self._return
