""" build script for acme2certifier """
from setuptools import setup
import sys
import os
exec(open('acme/version.py').read())
setup(name='acme2certifier',
      version=__version__,
      description='ACMEv2 server',
      url='https://github.com/grindsa/acme2certifier',
      author='grindsa',
      author_email='grindelsack@gmail.com',
      license='GPL',
      packages=['acme',
                'examples', 
                'examples.ca_handler', 
                'examples.db_handler', 
                'examples.django.acme', 
                'examples.django.acme.migrations', 
                'examples.django.acme.fixture',
                'examples.django.acme2certifier', 
                'examples.django', 
                'examples.nginx',
                'tools',                 
      ],
      package_data={
          'examples': ['*.py', '*.conf', '*.cfg'],
          'examples.nginx': ['*.conf', '*.ini', '*.service'],
          'examples.django.acme.fixture': ['*.yaml'],          
      },

      data_files = [('tools', ['docs/certifier.md'])],
      
      platforms='any',
      classifiers=[
          'Programming Language :: Python',
          'Development Status :: 4 - Beta',
          'Natural Language :: German',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
          'Operating System :: OS Independent',
          'Topic :: Software Development :: Libraries :: Python Modules'
          ],
      zip_safe=False,
      test_suite="test")
