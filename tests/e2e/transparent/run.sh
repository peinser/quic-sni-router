#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
for cmd in unshare ip nft python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "SKIP transparent netns integration: $cmd unavailable"
    exit 0
  fi
done
if [[ ! -x build/qsr_dataplane_tests ]]; then
  echo "SKIP transparent netns integration: build/qsr_dataplane_tests missing (run make build first)"
  exit 0
fi
# A mount namespace is needed too: `ip netns add` bind-mounts below /run/netns.
# A private tmpfs keeps the host's /run untouched.
if ! unshare -rnm sh -c 'mount -t tmpfs none /run && mkdir -p /run/netns' 2>/dev/null; then
  echo "SKIP transparent netns integration: cannot create isolated user/network/mount namespace"
  exit 0
fi
set +e
unshare -rnm sh -c 'mount -t tmpfs none /run && mkdir -p /run/netns && ip link set lo up && exec python3 tests/e2e/transparent/netns.py "$1"' \
  sh "$PWD/build/qsr_dataplane_tests"
status=$?
set -e
if [[ "$status" -eq 77 ]]; then
  echo "SKIP transparent netns integration: network namespace, veth or nft permissions unavailable"
  exit 0
fi
exit "$status"
