# -*- coding: utf-8 -*-
""" urls for acme django database """
from django.urls import re_path
from acme_srv import views

urlpatterns = [
    re_path(r'^acct', views.acct, name='acct'),
    re_path(r'^authz', views.authz, name='authz'),
    re_path(r'^cert', views.cert, name='cert'),
    re_path(r'^chall', views.chall, name='chall'),
    re_path(r'^directory$', views.directory, name='directory'),
    re_path(r'^newaccount$', views.newaccount, name='newaccount'),
    re_path(r'^key-change$', views.acct, name='acct'),
    re_path(r'^newnonce$', views.newnonce, name='newnonce'),
    re_path(r'^neworders$', views.neworders, name='neworders'),
    re_path(r'^order', views.order, name='order'),
    re_path(r'^revokecert', views.revokecert, name='revokecert'),
    re_path(r'^renewal-info', views.renewalinfo, name='renewalinfo'),
    re_path(r'^servername_get$', views.servername_get, name='servername_get'),
]
