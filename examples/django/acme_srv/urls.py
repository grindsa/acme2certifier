# -*- coding: utf-8 -*-
""" urls for acme django database """
from django.conf.urls import url
from acme_srv import views

urlpatterns = [
    url(r'^acct', views.acct, name='acct'),
    url(r'^authz', views.authz, name='authz'),
    url(r'^cert', views.cert, name='cert'),
    url(r'^chall', views.chall, name='chall'),
    url(r'^directory$', views.directory, name='directory'),
    url(r'^newaccount$', views.newaccount, name='newaccount'),
    url(r'^key-change$', views.acct, name='acct'),
    url(r'^newnonce$', views.newnonce, name='newnonce'),
    url(r'^neworders$', views.neworders, name='neworders'),
    url(r'^order', views.order, name='order'),
    url(r'^revokecert', views.revokecert, name='revokecert'),
    url(r'^servername_get$', views.servername_get, name='servername_get'),
]
