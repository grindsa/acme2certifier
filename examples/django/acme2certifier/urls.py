"""acme2certifier URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
# pylint: disable=C0330
from django.conf.urls import include, url
from django.contrib import admin
from acme_srv import views
from acme_srv.helper import load_config

# load config to set url_prefix
CONFIG = load_config()

# check ifwe need to prefix the url
if 'Directory' in CONFIG and 'url_prefix' in CONFIG['Directory']:
    prefix = CONFIG['Directory']['url_prefix'] + '/'
    if prefix.startswith('/'):
        prefix = prefix.lstrip('/')
else:
    prefix = ''

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', views.directory, name='index'),
    url(r'^directory$', views.directory, name='directory'),
    url(r'^{0}get_servername$'.format(prefix), views.servername_get, name='servername_get'),
    url(r'^{0}trigger$'.format(prefix), views.trigger, name='trigger'),
    url(r'^{0}housekeeping$'.format(prefix), views.housekeeping, name='housekeeping'),
    url(r'^{0}acme/'.format(prefix), include('acme_srv.urls'))
]

# check if we need to activate the url pattern for challenge verification
if 'CAhandler' in CONFIG and 'acme_url' in CONFIG['CAhandler']:
    urlpatterns.append(url(r'^{0}.well-known/acme-challenge/'.format(prefix), views.acmechallenge_serve, name='acmechallenge_serve'))
