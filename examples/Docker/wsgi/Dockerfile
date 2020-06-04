FROM ubuntu:20.04
LABEL maintainer="grindelsack@gmail.com"

ARG BRANCH
RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install --no-install-recommends -y python3-pip apache2 apache2-data libapache2-mod-wsgi-py3 curl

ENV APACHE_RUN_USER www-data
ENV APACHE_RUN_GROUP www-data
ENV APACHE_LOG_DIR /var/log/apache2

RUN echo "...downlading version: $BRANCH..."
RUN mkdir -p /tmp/acme2certifier && \
    curl -kL https://github.com/grindsa/acme2certifier/archive/$BRANCH.tar.gz | tar xz -C /tmp/acme2certifier --strip-components=1 && \
    pip3 install -r /tmp/acme2certifier/requirements.txt

RUN mkdir -p /var/www/acme2certifier/volume && \
    mkdir -p /var/www/acme2certifier/examples && \
    cp /tmp/acme2certifier/examples/apache_wsgi.conf /etc/apache2/sites-enabled/acme2certifier.conf && \
    a2enmod ssl && \
    rm /etc/apache2/sites-enabled/000-default.conf && \
    cp /tmp/acme2certifier/examples/acme2certifier_wsgi.py /var/www/acme2certifier/acme2certifier_wsgi.py && \
    cp -R /tmp/acme2certifier/examples/ca_handler /var/www/acme2certifier/examples/ && \
    cp /tmp/acme2certifier/examples/acme_srv.cfg /var/www/acme2certifier/examples/ && \
    cp /tmp/acme2certifier/examples/apache_wsgi_ssl.conf /var/www/acme2certifier/examples/ && \
    cp -R /tmp/acme2certifier/acme /var/www/acme2certifier/ && \
    cp -R /tmp/acme2certifier/tools /var/www/acme2certifier/ && \
    cp /tmp/acme2certifier/examples/db_handler/wsgi_handler.py /var/www/acme2certifier/acme/db_handler.py && \
    chown -R www-data.www-data /var/www/acme2certifier/ && \
    rm -rf /tmp/acme2certifier

COPY docker-entrypoint.sh /docker-entrypoint.sh

WORKDIR /var/www/acme2certifier/

ENTRYPOINT ["/docker-entrypoint.sh"]

# CMD ["bash"]
CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]

EXPOSE 80 443
