# -*- coding: utf-8 -*-
""" acme app main view """
from __future__ import unicode_literals

from django.http import HttpResponse
from django.http import JsonResponse
from acme.authorization import Authorization
from acme.account import Account
from acme.challenge import Challenge
from acme.directory import Directory
from acme.nonce import Nonce
from acme.order import Order
from acme.helper import get_url

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
    with Directory(DEBUG, get_url(request.META)) as cfg_dir:
        return JsonResponse(cfg_dir.directory_get())

def newaccount(request):
    """ new account """
    if request.method == 'POST':
        with Account(DEBUG, get_url(request.META)) as account:
            response_dic = account.new(request.body)
            # create the response
            response = JsonResponse(status=response_dic['code'], data=response_dic['data'])

            # generate additional header elements
            for element in response_dic['header']:
                response[element] = response_dic['header'][element]

            # send response
            return response
    else:
        return JsonResponse(status=405, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected POST.'})

def newnonce(request):
    """ new nonce """
    if request.method == 'HEAD':
        with Nonce(DEBUG) as nonce:
            response = HttpResponse('')
            # generate nonce
            response['Replay-Nonce'] = nonce.generate_and_add()
            return response
    else:
        return JsonResponse(status=400, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected HEAD.'})

def servername_get(request):
    """ get server name """
    with Directory(DEBUG, get_url(request.META)) as cfg_dir:
        return JsonResponse({'server_name' : cfg_dir.servername_get()})

def acct(request):
    """ xxxx command """
    with Account(DEBUG, get_url(request.META)) as account:
        response_dic = account.parse(request.body)
        # create the response
        response = JsonResponse(status=response_dic['code'], data=response_dic['data'])

        # generate additional header elements
        for element in response_dic['header']:
            response[element] = response_dic['header'][element]

        # send response
        return response

def neworders(request):
    """ new account """
    if request.method == 'POST':
        with Order(DEBUG, get_url(request.META)) as order:
            response_dic = order.new(request.body)
            # create the response
            response = JsonResponse(status=response_dic['code'], data=response_dic['data'])

            # generate additional header elements
            for element in response_dic['header']:
                response[element] = response_dic['header'][element]

            # send response
            return response
    else:
        return JsonResponse(status=405, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected POST.'})

def authz(request):
    """ new-authz command """
    if request.method == 'POST' or request.method == 'GET':
        with Authorization(DEBUG, get_url(request.META)) as authorization:
            if request.method == 'POST':
                response_dic = authorization.new_post(request.body)
            else:
                response_dic = authorization.new_get(request.build_absolute_uri())
            # create the response
            response = JsonResponse(status=response_dic['code'], data=response_dic['data'])

            # send response
            return response
    else:
        return JsonResponse(status=405, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected POST.'})

def chall(request):
    """ challenge command """
    with Challenge(DEBUG, get_url(request.META)) as challenge:
        if request.method == 'POST':
            response_dic = challenge.parse(request.build_absolute_uri(), request.body)
            # create the response
            response = JsonResponse(status=response_dic['code'], data=response_dic['data'])
            # generate additional header elements
            for element in response_dic['header']:
                response[element] = response_dic['header'][element]
            # send response
            return response
        elif request.method == 'GET':
            response_dic = challenge.get(request.build_absolute_uri())
            # create the response
            response = JsonResponse(status=response_dic['code'], data=response_dic['data'])

            # send response
            return response
        else:
            return JsonResponse(status=405, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected POST.'})

def order(request):
    """ new-authz command """
    if request.method == 'POST':
        with Order(DEBUG, get_url(request.META)) as order:
            response_dic = order.parse(request.body)
            # create the response
            response = JsonResponse(status=response_dic['code'], data=response_dic['data'])
            # generate additional header elements
            for element in response_dic['header']:
                response[element] = response_dic['header'][element]

            # send response
            return response
    else:
        return JsonResponse(status=405, data={'status':405, 'message':'Method Not Allowed', 'detail': 'Wrong request type. Expected POST.'})

#def blubb(request):
#    """ xxxx command """
#    with ACMEsrv(request.META['HTTP_HOST']) as acm:
#        return HttpResponse('ok')
# return JsonResponse(status=403, data={'status':403, 'message':'not that far', 'detail': 'we are ot that far.'})