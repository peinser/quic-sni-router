FROM harbor.peinser.com/dockerhub/ubuntu:24.04 AS build

ARG DEBIAN_FRONTEND=noninteractive
ARG QSR_CPU_TARGET=
ARG QSR_ENABLE_LTO=OFF
ARG QSR_ENABLE_PACKET_DEBUG=OFF
WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    clang \
    cmake \
    libc6-dev \
    libssl-dev \
    libyaml-dev \
    ninja-build \
    pkg-config \
    && if [ "${QSR_ENABLE_LTO}" = "ON" ]; then \
        apt-get install -y --no-install-recommends lld llvm; \
    fi \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang \
        $(if [ "${QSR_ENABLE_LTO}" = "ON" ]; then printf '%s' '-DCMAKE_AR=llvm-ar -DCMAKE_RANLIB=llvm-ranlib'; fi) \
        -DQSR_CPU_TARGET="${QSR_CPU_TARGET}" \
        -DQSR_ENABLE_LTO="${QSR_ENABLE_LTO}" \
        -DQSR_ENABLE_PACKET_DEBUG="${QSR_ENABLE_PACKET_DEBUG}" \
    && cmake --build build \
    && ctest --test-dir build --output-on-failure

FROM harbor.peinser.com/dockerhub/ubuntu:24.04 AS production
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="quic-sni-router" \
      org.opencontainers.image.description="A small QUIC SNI router for UDP/443 HTTP/3 services with pod-terminated TLS/mTLS" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/Peinser/quic-sni-router" \
      org.opencontainers.image.vendor="Peinser BV" \
      org.opencontainers.image.licenses="Apache-2.0"
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libyaml-0-2 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 10001 -g nogroup qsr
COPY --from=build /src/build/quic-sni-router /usr/local/bin/quic-sni-router
EXPOSE 443/udp
STOPSIGNAL SIGTERM
USER qsr
ENTRYPOINT ["/usr/local/bin/quic-sni-router"]
CMD ["/config/router.yaml"]

FROM production AS e2e
COPY tests/e2e/http3/router.yaml /config/router.yaml
