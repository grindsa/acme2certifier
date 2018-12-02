from django.conf.urls import url
from acme import views

urlpatterns = [
    url(r'^directory$', views.directory, name='directory'),	
    url(r'^newnonce$', views.newnonce, name='newnonce'),	
    url(r'^newaccount$', views.newaccount, name='newaccount'),	    
    url(r'^get_servername$', views.get_servername, name='get_servername'),
    # url(r'^new_authz$', views.new_authz, name='new_authz'),    
]