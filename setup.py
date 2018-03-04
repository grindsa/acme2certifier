from setuptools import setup

setup(name='acme2certifier',
    version='0.0.1',
    description='acme v2 serer for NetGuard Certificate Manager / Insta Certifier.',
    url='https://github.com/grindsa/acme2certifier',
    author='grindsa',
    author_email='grindelsack@gmail.com',
    license='MIT',
    packages=['acme2certifier'],
    platforms='any',
    install_requires=[
        'cgi'
    ],
    classifiers = [
        'Programming Language :: Python',
        'Development Status :: 4 - Beta',
        'Natural Language :: German',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules'
        ],    
    zip_safe=False,
    test_suite="test")