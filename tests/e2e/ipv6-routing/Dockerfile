ARG HTTP3_IMAGE=qsr-ipv6-routing-http3:latest
FROM ${HTTP3_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 tcpdump \
    && rm -rf /var/lib/apt/lists/*
COPY routing.py /app/routing.py
