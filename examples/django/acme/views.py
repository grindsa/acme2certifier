# -*- coding: utf-8 -*-
""" acme app main view """
from __future__ import unicode_literals

from django.shortcuts import render
from django.http import HttpResponse
from django.http import JsonResponse
from acme.acmesrv import *

def pretty_request(request):
    """ print request details for debugging """
    headers = ''
    for header, value in request.META.items():
        if not header.startswith('HTTP'):
            continue
        header = '-'.join([h.capitalize() for h in header[5:].lower().split('_')])
        headers += '{}: {}\n'.format(header, value)

    return (
        '{method} HTTP/1.1\n'
        'Content-Length: {content_length}\n'
        'Content-Type: {content_type}\n'
        '{headers}\n\n'
        '{body}'
    ).format(
        method=request.method,
        content_length=request.META['CONTENT_LENGTH'],
        content_type=request.META['CONTENT_TYPE'],
        headers=headers,
        body=request.body,
)


def directory(request):
    """ get directory """
    with ACMEsrv(request.META['HTTP_HOST']) as acm:
        return JsonResponse(acm.get_directory())
 
def newaccount(request):
    """ new account """
    with ACMEsrv(request.META['HTTP_HOST']) as acm:
        print(pretty_request(request))
        return HttpResponse('ok')
        
def newnonce(request):
    """ new nonce """
    with ACMEsrv(request.META['HTTP_HOST']) as acm:
        response = HttpResponse('ok')
        response['Replay-Nonce'] = acm.newnonce()
        return response

def get_servername(request):
    """ get server name """
    with ACMEsrv(request.META['HTTP_HOST']) as acm:
        return JsonResponse({'server_name' : acm.get_server_name()})

def blubb(request):
    """ xxxx command """
    with ACMEsrv(request.META['HTTP_HOST']) as acm:
        return HttpResponse('ok')
