"""acme2certifier URL Configuration"""
from django.conf.urls import include, url
from django.contrib import admin
from acme_srv import views
from acme_srv.helper import load_config

# load config to set url_prefix
CONFIG = load_config()

# check ifwe need to prefix the url
if 'Directory' in CONFIG and 'url_prefix' in CONFIG['Directory']:
    PREFIX = CONFIG['Directory']['url_prefix'] + '/'
    if PREFIX.startswith('/'):
        PREFIX = PREFIX.lstrip('/')
else:
    PREFIX = ''

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', views.directory, name='index'),
    url(r'^directory$', views.directory, name='directory'),
    url(rf'^{PREFIX}get_servername$', views.servername_get, name='servername_get'),
    url(rf'^{PREFIX}trigger$', views.trigger, name='trigger'),
    url(rf'^{PREFIX}housekeeping$', views.housekeeping, name='housekeeping'),
    url(rf'^{PREFIX}acme/', include('acme_srv.urls'))
]

# check if we need to activate the url pattern for challenge verification
if 'CAhandler' in CONFIG and 'acme_url' in CONFIG['CAhandler']:
    urlpatterns.append(url(rf'^{PREFIX}.well-known/acme-challenge/', views.acmechallenge_serve, name='acmechallenge_serve'))
