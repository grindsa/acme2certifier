#!/usr/bin/python
# -*- coding: utf-8 -*-
""" customized class for django json response """
import json
from django.http import HttpResponse
from django.core.serializers.json import DjangoJSONEncoder


class JsonResponse(HttpResponse):
    """
    An HTTP response class that consumes data to be serialized to JSON.
    and changes the contentent type base do status code
    """

    def __init__(self, data, encoder=DjangoJSONEncoder, safe=True,
                 json_dumps_params=None, **kwargs):
        if safe and not isinstance(data, dict):
            raise TypeError(
                'In order to allow non-dict objects to be serialized set the '
                'safe parameter to False.'
            )
        if json_dumps_params is None:
            json_dumps_params = {}

        if 'status' in kwargs and kwargs['status'] > 201:
            kwargs.setdefault('content_type', 'problem+json')
        else:
            kwargs.setdefault('content_type', 'application/json')

        data = json.dumps(data, cls=encoder, **json_dumps_params)
        super().__init__(content=data, **kwargs)
