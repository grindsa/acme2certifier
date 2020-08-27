FROM ubuntu:20.04
LABEL maintainer="grindelsack@gmail.com"

RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install --no-install-recommends -y \
    python3-pip \
    apache2 \
    apache2-data \
    libapache2-mod-wsgi-py3 \
    curl \
    python3-cryptography \    
 && rm -rf /var/lib/apt/lists/*

# install python requirements
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

ENV APACHE_RUN_USER www-data
ENV APACHE_RUN_GROUP www-data
ENV APACHE_LOG_DIR /var/log/apache2

# create folders for acme2certifier
RUN mkdir -p /var/www/acme2certifier/volume && \
    mkdir -p /var/www/acme2certifier/examples /var/www/acme2certifier/examples/

COPY examples/apache_wsgi.conf /etc/apache2/sites-enabled/acme2certifier.conf
COPY examples/acme2certifier_wsgi.py /var/www/acme2certifier/acme2certifier_wsgi.py
COPY examples/ca_handler/ /var/www/acme2certifier/examples/ca_handler
COPY examples/acme_srv.cfg /var/www/acme2certifier/examples/
COPY examples/apache_wsgi_ssl.conf /var/www/acme2certifier/examples/
COPY examples/db_handler/wsgi_handler.py /var/www/acme2certifier/acme/db_handler.py
COPY acme/ /var/www/acme2certifier/acme
COPY tools/ /var/www/acme2certifier/tools
RUN chown -R www-data:www-data /var/www/acme2certifier/

# final apache2 changes
RUN sed -i "s/\${APACHE_LOG_DIR}\/error.log/\/dev\/stderr/g" /etc/apache2/apache2.conf && \
    a2enmod ssl && \
    rm /etc/apache2/sites-enabled/000-default.conf

COPY examples/Docker/apache2/wsgi/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod a+rx /docker-entrypoint.sh

WORKDIR /var/www/acme2certifier/

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]

EXPOSE 80 443
