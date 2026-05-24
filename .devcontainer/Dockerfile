FROM harbor.peinser.com/dockerhub/ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    afl++ \
    bash \
    build-essential \
    ca-certificates \
    clang-18 \
    clang-format-18 \
    clang-tidy-18 \
    clang-tools-18 \
    clangd-18 \
    libclang-rt-18-dev \
    cmake \
    cppcheck \
    curl \
    gdb \
    gcc-13 \
    git \
    libssl-dev \
    libyaml-dev \
    lcov \
    lld-18 \
    make \
    mold \
    ninja-build \
    openssh-client \
    pkg-config \
    valgrind \
    vim \
    && update-alternatives --install /usr/bin/clang   clang   /usr/bin/clang-18   100 \
    && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-18 100 \
    && update-alternatives --install /usr/bin/clangd  clangd  /usr/bin/clangd-18  100 \
    && update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-18 100 \
    && update-alternatives --install /usr/bin/clang-tidy   clang-tidy   /usr/bin/clang-tidy-18   100 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://opencode.ai/install | bash

WORKDIR /workspace
