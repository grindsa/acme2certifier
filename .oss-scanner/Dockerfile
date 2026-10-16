# Anthropic OSS Scanner build image for acme2certifier.
# Build context is the repository root. Network is available only during this build.
FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      build-essential \
      git \
      openssl \
      libkrb5-dev \
      python3 \
      python3-pip \
      python3-venv \
      python3-dev \
      python3-gssapi \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

RUN python3 -m venv /opt/a2c-venv
ENV PATH="/opt/a2c-venv/bin:${PATH}"

# Match CI (.github/workflows/quality-python.yml): test + gssapi extras, impacket for MS-ICPR paths.
RUN pip install --upgrade pip build \
    && pip install --no-cache-dir ".[test,gssapi]" \
    && pip install --no-cache-dir pytest impacket

RUN cp examples/acme_srv.cfg acme2certifier/acme_srv/

# Smoke-test the image. Failures are reported but must not abort enrollment import.
RUN pytest -q --tb=no || echo "WARNING: pytest reported failures"
