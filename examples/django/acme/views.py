# -*- coding: utf-8 -*-
""" acme app main view """
from __future__ import unicode_literals

from django.http import HttpResponse
from django.http import JsonResponse
from acme.acmesrv import ACMEsrv

DEBUG = True

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
        body=request.body, )

def directory(request):
    """ get directory """
    with ACMEsrv(DEBUG, request.META['HTTP_HOST']) as acm:
        return JsonResponse(acm.directory_get())

def newaccount(request):
    """ new account """
    if request.method == 'POST':
        with ACMEsrv(DEBUG, request.META['HTTP_HOST']) as acm:
            (code, message, detail) = acm.account_new(request.body)
            # create the response
            response = JsonResponse(status=code, data={'status':code, 'message':message, 'detail': detail})
            # generate new nonce
            response['Replay-Nonce'] = acm.nonce_generate_and_add()
            return response
    else:
        return JsonResponse(status=400, data={'status':400, 'message':'bad request ', 'detail': 'Wrong request type. Expected POST.'})

def newnonce(request):
    """ new nonce """
    if request.method == 'HEAD':
        with ACMEsrv(DEBUG, request.META['HTTP_HOST']) as acm:
            response = HttpResponse('')
            # generate nonce
            response['Replay-Nonce'] = acm.nonce_generate_and_add()
            return response
    else:
        return JsonResponse(status=400, data={'status':400, 'message':'bad request ', 'detail': 'Wrong request type. Expected HEAD.'})

def servername_get(request):
    """ get server name """
    with ACMEsrv(DEBUG, request.META['HTTP_HOST']) as acm:
        return JsonResponse({'server_name' : acm.servername_get()})

#def blubb(request):
#    """ xxxx command """
#    with ACMEsrv(request.META['HTTP_HOST']) as acm:
#        return HttpResponse('ok')
