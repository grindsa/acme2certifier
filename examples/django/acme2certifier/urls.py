"""acme2certifier URL Configuration"""
from django.urls import include, re_path
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
    re_path(r'^admin/', admin.site.urls),
    re_path(r'^$', views.directory, name='index'),
    re_path(r'^directory$', views.directory, name='directory'),
    re_path(rf'^{PREFIX}get_servername$', views.servername_get, name='servername_get'),
    re_path(rf'^{PREFIX}trigger$', views.trigger, name='trigger'),
    re_path(rf'^{PREFIX}housekeeping$', views.housekeeping, name='housekeeping'),
    re_path(rf'^{PREFIX}acme/', include('acme_srv.urls'))
]

# check if we need to activate the url pattern for challenge verification
if 'CAhandler' in CONFIG and 'acme_url' in CONFIG['CAhandler']:
    urlpatterns.append(re_path(rf'^{PREFIX}.well-known/acme-challenge/', views.acmechallenge_serve, name='acmechallenge_serve'))
