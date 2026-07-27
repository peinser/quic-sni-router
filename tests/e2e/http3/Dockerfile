# Public by default so `make test-e2e` works outside the Peinser network.
# Override with --build-arg BASE_IMAGE=<mirror> to use a pull-through cache.
ARG BASE_IMAGE=docker.io/library/python:3.12-slim
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir aioquic==1.2.0

WORKDIR /app
COPY *.py ./
