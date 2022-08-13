#!/usr/bin/python
# -*- coding: utf-8 -*-
""" ThreadWithReturnValue class """
# pylint: disable=r0913
from threading import Thread


class ThreadWithReturnValue(Thread):
    """ main class """
    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, *, daemon=None):
        Thread.__init__(self, group, target, name, args, kwargs, daemon=daemon)

        self._return = None

    def run(self):
        if self._target is not None:
            self._return = self._target(*self._args, **self._kwargs)

    def join(self, timeout=None):
        Thread.join(self, timeout=timeout)
        return self._return
