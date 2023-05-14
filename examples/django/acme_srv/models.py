# -*- coding: utf-8 -*-
""" model for acme django database """
from __future__ import unicode_literals
from django.db import models


# Create your models here.
class Nonce(models.Model):
    """ nonce table """
    nonce = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

    def __unicode__(self):
        return self.nonce


class Account(models.Model):
    """ account table """
    name = models.CharField(max_length=15, unique=True)
    jwk = models.TextField(blank=True)
    alg = models.CharField(max_length=10)
    contact = models.CharField(max_length=255)
    eab_kid = models.TextField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __unicode__(self):
        return self.contact


class Cliaccount(models.Model):
    """ account table """
    name = models.CharField(max_length=15, unique=True)
    jwk = models.TextField(blank=True)
    contact = models.CharField(max_length=255)
    reportadmin = models.BooleanField(default=False)
    cliadmin = models.BooleanField(default=False)
    certificateadmin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


class Status(models.Model):
    """ order status """
    name = models.CharField(max_length=15, unique=True)

    def __unicode__(self):
        return self.name


class Order(models.Model):
    """ order table """
    name = models.CharField(max_length=15, unique=True)
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    notbefore = models.IntegerField(default=0)
    notafter = models.IntegerField(default=0)
    identifiers = models.TextField()
    status = models.ForeignKey(Status, default=2, on_delete=models.CASCADE)
    expires = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __unicode__(self):
        return self.name


class Authorization(models.Model):
    """ order table """
    name = models.CharField(max_length=15, unique=True)
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    type = models.CharField(max_length=5)
    value = models.TextField()
    token = models.CharField(max_length=64, blank=True)
    expires = models.IntegerField(default=0)
    status = models.ForeignKey(Status, default=1, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __unicode__(self):
        return self.name


class Challenge(models.Model):
    """ order table """
    name = models.CharField(max_length=15, unique=True)
    authorization = models.ForeignKey(Authorization, on_delete=models.CASCADE)
    type = models.CharField(max_length=15)
    token = models.CharField(max_length=64)
    expires = models.IntegerField(default=0)
    status = models.ForeignKey(Status, default=2, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    keyauthorization = models.CharField(max_length=128, blank=True)
    validated = models.IntegerField(default=0)

    def __unicode__(self):
        return self.name


class Certificate(models.Model):
    """ order table """
    name = models.CharField(max_length=15, unique=True)
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    csr = models.TextField(blank=True, null=True)
    cert = models.TextField(blank=True, null=True)
    cert_raw = models.TextField(blank=True, null=True)
    error = models.TextField(blank=True, null=True)
    poll_identifier = models.TextField(blank=True, null=True)
    expire_uts = models.IntegerField(default=0)
    issue_uts = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True, null=True)

    def __unicode__(self):
        return self.name


class Housekeeping(models.Model):
    """ housekeeping """
    name = models.CharField(max_length=15, unique=True)
    value = models.CharField(max_length=30, blank=True)
    modified_at = models.DateTimeField('value', auto_now_add=True, null=True)


class Cahandler(models.Model):
    """ housekeeping """
    name = models.CharField(max_length=50, unique=True)
    value1 = models.CharField(max_length=250, blank=True)
    value2 = models.CharField(max_length=250, blank=True)
    created_at = models.DateTimeField('value', auto_now_add=True, null=True)
