#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
for cmd in unshare nsenter ip python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "SKIP transparent netns integration: $cmd unavailable"
    exit 0
  fi
done
if [[ ! -x build/qsr_dataplane_tests ]]; then
  echo "SKIP transparent netns integration: build/qsr_dataplane_tests missing (run make build first)"
  exit 0
fi
# A fresh user and network namespace: unprivileged, and every link, address,
# rule and nft table disappears with it instead of touching the host.
if ! unshare -rn true 2>/dev/null; then
  echo "SKIP transparent netns integration: cannot create a user and network namespace"
  exit 0
fi
set +e
QSR_TRANSPARENT_NETNS=1 unshare -rn sh -c 'ip link set lo up && exec python3 tests/e2e/transparent/netns.py "$1"' \
  sh "$PWD/build/qsr_dataplane_tests"
status=$?
set -e
if [[ "$status" -eq 77 ]]; then
  echo "SKIP transparent netns integration: veth or address setup not permitted"
  exit 0
fi
exit "$status"
