FROM ubuntu:22.04
LABEL maintainer="grindelsack@gmail.com"

RUN apt-get update  && \
    DEBIAN_FRONTEND="noninteractive" apt-get -y install --no-install-recommends tzdata && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
    apache2 \
    apache2-data \
    curl \
    krb5-user \
    libapache2-mod-wsgi-py3 \
    libgssapi-krb5-2 \
    libkrb5-3 \
    python3-gssapi \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*


# install python requirements
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt &&\
    mkdir -p /usr/local/soap-srv/acme_srv && \
	mkdir -p /usr/local/soap-srv/examples/ca_handler

COPY examples/soap/mock_soap_srv.py /usr/local/soap-srv/
COPY acme_srv/helper.py acme_srv/version.py /usr/local/soap-srv/acme_srv/
COPY examples/ca_handler/xca_ca_handler.py /usr/local/soap-srv/examples/ca_handler/xca_ca_handler.py
COPY examples/Docker/soap-srv/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod a+rx /docker-entrypoint.sh

WORKDIR /tmp

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["python3", "/usr/local/soap-srv/mock_soap_srv.py", "-d", "-c", "/etc/soap-srv/soap_srv.cfg"]
# CMD ["/bin/bash"]

EXPOSE 80
