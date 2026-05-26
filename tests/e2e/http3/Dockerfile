FROM harbor.peinser.com/dockerhub/python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir aioquic==1.2.0

WORKDIR /app
COPY *.py ./
