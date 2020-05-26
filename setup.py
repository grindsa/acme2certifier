from setuptools import setup
exec(open('acme/version.py').read())
setup(name='acme2certifier',
    version=__version__,
    description='ACMEv2 server',
    url='https://github.com/grindsa/acme2certifier',
    author='grindsa',
    author_email='grindelsack@gmail.com',
    license='GPL',
    packages=['acme2certifier'],
    platforms='any',
    classifiers = [
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