#!/usr/bin/env sh
set -eu

name="${1:?backend name required}"
port="${2:?udp port required}"

exec socat -v "UDP-LISTEN:${port},fork,reuseaddr" "SYSTEM:printf '${name}:'; cat"
