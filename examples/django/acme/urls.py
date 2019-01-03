from django.conf.urls import url
from acme import views

urlpatterns = [
    url(r'^directory$', views.directory, name='directory'),
    url(r'^newnonce$', views.newnonce, name='newnonce'),
    url(r'^newaccount$', views.newaccount, name='newaccount'),
    url(r'^servername_get$', views.servername_get, name='servername_get'),
    url(r'^acct', views.acct, name='acct'),
    url(r'^authz', views.authz, name='authz'),
    url(r'^neworders$', views.neworders, name='neworders'),
    url(r'^chall', views.chall, name='chall'),
    url(r'^order', views.order, name='order'),
    url(r'^cert', views.cert, name='cert'),
]
