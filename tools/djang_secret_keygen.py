#!/usr/bin/python3
from django.core.management.utils import get_random_secret_key  
print(get_random_secret_key())