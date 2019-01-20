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

class Account(models.Model):
    """ account table """
    name = models.CharField(max_length=15, unique=True)
    alg = models.CharField(max_length=10)
    exponent = models.CharField(max_length=10)
    kty = models.CharField(max_length=10)
    modulus = models.CharField(max_length=1024)
    contact = models.CharField(max_length=15)
    created_at = models.DateTimeField(auto_now_add=True)
    def __unicode__(self):
        return self.contact

class Status(models.Model):
    """ order status """
    name = models.CharField(max_length=15, unique=True) 
    def __unicode__(self):
        return self.name    
        
class Order(models.Model):
    """ order table """
    name = models.CharField(max_length=15, unique=True)
    account = models.ForeignKey(Account)
    notbefore = models.IntegerField(default=0)
    notafter = models.IntegerField(default=0)
    identifiers = models.CharField(max_length=1048)
    status = models.ForeignKey(Status, default=2)
    expires = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)    
    def __unicode__(self):
        return self.name
             
class Authorization(models.Model):
    """ order table """
    name = models.CharField(max_length=15, unique=True)
    order = models.ForeignKey(Order) 
    type = models.CharField(max_length=5)
    value = models.CharField(max_length=64)
    token = models.CharField(max_length=64, blank=True)   
    expires = models.IntegerField(default=0)  
    status = models.ForeignKey(Status, default=1)    
    created_at = models.DateTimeField(auto_now_add=True)    
    def __unicode__(self):
        return self.name    
        
class Challenge(models.Model):
    """ order table """
    name = models.CharField(max_length=15, unique=True)
    authorization = models.ForeignKey(Authorization) 
    type = models.CharField(max_length=10)
    token = models.CharField(max_length=64)    
    expires = models.IntegerField(default=0)    
    status = models.ForeignKey(Status, default=2)    
    created_at = models.DateTimeField(auto_now_add=True)  
    keyauthorization = models.CharField(max_length=128, blank=True)  
    def __unicode__(self):
        return self.name          

class Certificate(models.Model):
    """ order table """
    name = models.CharField(max_length=15, unique=True)
    order = models.ForeignKey(Order)    
    csr = models.TextField(blank=True) 
    cert = models.TextField(blank=True)  
    cert_raw = models.TextField(blank=True)      
    error = models.TextField(blank=True)      
    created_at = models.DateTimeField(auto_now_add=True)  
    def __unicode__(self):
        return self.name         
        