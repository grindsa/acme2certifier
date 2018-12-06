# -*- coding: utf-8 -*-
""" model for acme django database """
from __future__ import unicode_literals

from django.db import models

# Create your models here.
class Nonce(models.Model):
    """ nonce table """
    nonce = models.CharField(max_length=30)
    created_at = models.DateTimeField(auto_now_add=True)
    def __unicode__(self):
        return self.nonce
