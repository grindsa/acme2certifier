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
    # url(r'^new_authz$', views.new_authz, name='new_authz'),
]
