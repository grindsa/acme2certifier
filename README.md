# acme2certifier

acme2certifier is development project to create an ACME protocol proxy. Main intention is to provide ACME services on CA servers which do not support this protocol yet. It consists of two libraries:

- acme/*.py - a bunch of classes implementing ACME server functionality based on [draft-ietf-acme-acme-18](https://tools.ietf.org/html/draft-ietf-acme-acme-18)
- ca_handler.py - interface towards CA server. In this project I am connecting to Insta Certfier by using REST. However, the intention of this library is to be modular that an adaption to other CA servers would be straight forward

## Disclaimer
I am running this project as my RD guys told me that it won’t be possible :-)

So far I am using [acme.sh](https://github.com/Neilpang/acme.sh) and [Certbot](https://certbot.eff.org/) to test the server. Other clients are on my list for later testing. In case you are bored, feel free to test other came ACME clients and raise [issues](https://github.com/grindsa/acme2certifier/issues/new) if something does not work as expected.

[Commandline parameters used for testing](acme-clients.md)

I am not a professional developer. Keep this in mind while laughing about my code and don’t forget to send patches.

## Project status

So far, the library is far from being useful for either lab or production usage as only the below ACME functions are supported

- "directory" resource [(Section 7.1.1)](https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.1.1)
- "newNonce" resource  [(Section 7.2)](https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.2)
- "newAccount" resource [(Section 7.3)](https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.3)
    - Finding an Account URL Given a Key [(Section 7.3.1)](https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.3.1)
    - Account Deactivation [(Section 7.3.6)](https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.3.6)
- "new-order" resource [(Section 7.4)](https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.4)
- "order finalization" [(Section 7.4)](https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.4)
- "certificate download" [(Section 7.4.2)](https://tools.ietf.org/html/draft-ietf-acme-acme-18#section-7.4.2)
- "authz" resource [(Section 7.5)](https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.5)
- "challenge" resource [(Section 7.5.1)](https://tools.ietf.org/html/draft-ietf-acme-acme-16#section-7.5.1)

<span style="color:red;">IMPORTANT: The current version does NOT perform Identifier validation. In the current version the acme server will change the status of each callenge to "valid" forcing an acme client to send the CSR immediately.</span> 


Additional funitonality will be added over time. If you are badly missing certain functionality please raise an [issue](https://github.com/grindsa/acme2certifier/issues/new) to let me know.

# Installation
The proxy can run either as Django project or as plain wsgi-script

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
root@rlh:~# chown -R www-data.www-data /var/www/acme/
```

## Installation as Django project

1. create a new Django project called acme2certier
```
missing
```
2. create a new app inside your project called "acme"
```
missing
```
3. copy the content of the folder "examples/django/acme2certifier" into the "acme2certifer" folder of your project
4. copy the content of the folder "example/django/acme" into the "acme" folder created in step 2

## Contributing

Please read [CONTRIBUTING.md](https://github.com/grindsa/acme2certifier/blob/master/CONTRIBUTING.md) for details on my code of conduct, and the process for submitting pull requests.
Please note that I have a life besides programming. Thus, expect a delay in answering.

## Versioning

I use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/grindsa/dkb-robo/tags).

## License

This project is licensed under the MIT license - see the [LICENSE.md](https://github.com/grindsa/acme2certifier/blob/master/LICENSE) file for details
