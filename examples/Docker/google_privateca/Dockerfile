# Google Private CAS REST mock (enrollment / revoke subset).
# Build from this directory:
#   docker build -t a2c-google-cas-mock .
FROM python:3.12-slim

WORKDIR /opt/google_privateca

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pki.py bootstrap_ca.py server.py ./

# Mount host data at /data (see compose.yaml):
#   server-cert.pem / server-key.pem  → optional HTTPS
#   ca/                               → issuing PKI (bootstrapped if missing)
# Bind-mounted host dirs must be writable by uid/gid 1000.
RUN groupadd --gid 1000 casmock \
    && useradd --uid 1000 --gid casmock --home-dir /opt/google_privateca \
        --shell /usr/sbin/nologin casmock \
    && mkdir -p /data/ca \
    && chown -R casmock:casmock /opt/google_privateca /data
VOLUME ["/data"]

ENV MOCK_LISTEN=0.0.0.0:8080 \
    MOCK_PROJECT=demo \
    MOCK_LOCATION=europe-west1 \
    MOCK_POOL=demo-pool \
    MOCK_ISSUING_CA_ID=mock-issuing-ca \
    MOCK_DATA_DIR=/data \
    MOCK_CA_DIR=/data/ca \
    MOCK_TLS_CERT=/data/server-cert.pem \
    MOCK_TLS_KEY=/data/server-key.pem

EXPOSE 8080

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh \
    && chown casmock:casmock /docker-entrypoint.sh

USER casmock

ENTRYPOINT ["/docker-entrypoint.sh"]
