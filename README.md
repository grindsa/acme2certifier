# acme2certifier

acme2cerfier is development project to create an ACME protocol proxy. Main intention is to provide ACME services on CA service which do not support this protocol yet. It consists of two libraries:

- acmesrv.py - implementing ACME server functionality based of <link>
- ca_client.py - (not developed yet interface) towards CA server. In this project I am connecting via REST-API to Insta Certfier however the intention of this library is to be modular that an adaption to other CA servers should be straight forward

## Disclaimer
I am running this project as my RD guys told me it won’t be possible :-)

I am not a professional developer. Keep this in mind while laughing about my code quality and don’t forget to send patches.

## Project status

So far, the library is far from being useful for either lab or production usage as only the below ACME functions are supported

- "directory" resource (Section 7.1.1)
- "newNonce" resource (Section 7.2)
- "newAccount" resource (Section 7.3)


# Installation
The proxy can run either as Django project or as plain wsgi script

## Installation as Django project

1. create a new Django project called acme2certier
```
missing
```
2. crate a new app inside your project called "acme"
```
missing
```
3. copy the content of the folder "examples/django/acme2certifier" into the "acme2certifer" folder of your project
4. copy the content of the folder "example/django/acme" into the "acme" folder created in step 2


## Installation as wsgi script

### Installation on apache2

1. check of the wsgi module is running on your apache2
```
root@rlh:~# apache2ctl -M | grep -i wsgi
 wsgi_module (shared)
root@rlh:~#
```
if the wsgi_module is not enabled please check the internet how to do this.

2. download the archive and unpack it.
3. copy the file "example/apache_acme.conf" to "/etc/apache2/sites-available" and modify it according to you needs.
4. activate the virtual server
```
root@rlh:~# a2ensite acme_acme.conf
```
5. create a directory /var/www/acme
6. copy the file acme2certifier_wsgi.py to /var/www/acme
7. create a directory /var/www/acme/acme
8. copy the content of the acme -directory to /var/www/acme/acme
9. ensure that the all files and directories under /var/www/acme are owned by the user running the webserver
```
root@rlh:~# chown -R www-data.www-data /var/www/acme/^C
```

### check if wsgi module is enabled

root@rlh:~# apache2ctl -M | grep -i wsgi
 wsgi_module (shared)
root@rlh:~#

### install module
sudo apt-get install libapache2-mod-wsgi

sudo a2enmod wsgi 


## Contributing

Please read [CONTRIBUTING.md](https://github.com/grindsa/acme2certifier/blob/master/CONTRIBUTING.md) for details on my code of conduct, and the process for submitting pull requests.
Please note that I have a life besides programming. Thus, expect a delay in answering.

## Versioning

I use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/grindsa/dkb-robo/tags). 

## License

This project is licensed under the MIT license - see the [LICENSE.md](https://github.com/grindsa/acme2certifier/blob/master/LICENSE) file for details
