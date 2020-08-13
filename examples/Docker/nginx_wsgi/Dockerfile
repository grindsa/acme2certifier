# FROM centos:7
FROM centos
LABEL maintainer="grindelsack@gmail.com"

ARG BRANCH=master
RUN yum install -y epel-release && yum update -y && yum upgrade -y
RUN yum install -y python3 python3-pip nginx  python3-devel gcc

# create folders for acme2certifier
RUN mkdir -p /tmp/acme2certifier && \
    curl -kL https://github.com/grindsa/acme2certifier/archive/dock_nginx.tar.gz | tar xz -C /tmp/acme2certifier --strip-components=1 && \
    pip3 install -r /tmp/acme2certifier/requirements.txt && \
    pip3 install supervisor && \
    pip3 install uwsgi

RUN mkdir -p /opt/acme2certifier/volume && \
    mkdir -p /opt/acme2certifier/examples && \
    mkdir -p /run/uwsgi && \
    cp /tmp/acme2certifier/examples/acme2certifier_wsgi.py /opt/acme2certifier/acme2certifier_wsgi.py && \
    cp -R /tmp/acme2certifier/examples/ca_handler /opt/acme2certifier/examples/ && \    
    cp /tmp/acme2certifier/examples/acme_srv.cfg /opt/acme2certifier/examples/ && \    
    cp -R /tmp/acme2certifier/acme /opt/acme2certifier/ && \
    cp -R /tmp/acme2certifier/tools /opt/acme2certifier/ && \
    cp /tmp/acme2certifier/examples/db_handler/wsgi_handler.py /opt/acme2certifier/acme/db_handler.py && \
    cp /tmp/acme2certifier/examples/nginx/acme2certifier.ini /opt/acme2certifier && \
    cp /tmp/acme2certifier/examples/nginx/supervisord.conf /etc && \
    chown -R nginx /opt/acme2certifier/acme
    # rm -rf /tmp/acme2certifier

COPY /tmp/acme2certifier/examples/Docker/nginx_wsgi/docker-entrypoint.sh /docker-entrypoint.sh

WORKDIR /opt/acme2certifier

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/local/bin/supervisord"]

EXPOSE 80 443
