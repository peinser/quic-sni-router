#!/usr/bin/env bash

set -euo pipefail

export LANG=C.UTF-8
export LC_ALL=C.UTF-8

if [ -f /root/.gitconfig.host ]; then
  cp /root/.gitconfig.host /root/.gitconfig
fi

# Pre-generate compile_commands.json so clangd works in the IDE before the
# first manual `make build`. Skipped if a build dir already exists so we don't
# clobber an in-progress configuration.
if [ ! -f /workspace/build/compile_commands.json ]; then
  cmake -S /workspace -B /workspace/build -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang-18 >/dev/null 2>&1 || true
fi
