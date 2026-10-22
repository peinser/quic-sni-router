#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

project="qsr-ipv6-routing-$$"
router_image="${QSR_ROUTER_IMAGE:-qsr-ipv6-routing-router:latest}"
http3_image="qsr-ipv6-routing-http3:latest"
tools_image="qsr-ipv6-routing-tools:latest"

cleanup() {
  rc=$?
  if [ "$rc" -ne 0 ]; then
    for role in router tools client; do
      docker logs "${project}-${role}" >&2 || true
    done
    docker exec "${project}-tools" python /app/routing.py diagnostics || true
  fi
  docker rm -f "${project}-router" "${project}-client" "${project}-tools" >/dev/null 2>&1 || true
  docker network rm "${project}-public" "${project}-warp" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -z "${QSR_ROUTER_IMAGE:-}" ]; then
  docker build -t "$router_image" -f ../../../docker/Dockerfile --target e2e ../../..
fi
docker build -t "$http3_image" -f ../http3/Dockerfile ../http3
docker build -t "$tools_image" --build-arg HTTP3_IMAGE="$http3_image" .

# Internal bridges: no external route or host sysctl changes are needed.
docker network create --internal --ipv6 --subnet fd71:7::/64 "${project}-public" >/dev/null
docker network create --internal --ipv6 --subnet fd71:8::/64 "${project}-warp" >/dev/null
for role in tools client; do
  suffix=10
  [ "$role" != client ] || suffix=20
  docker run -d --name "${project}-${role}" --network "${project}-public" \
    --ip6 "fd71:7::${suffix}" --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW \
    "$tools_image" sleep infinity >/dev/null
  docker network connect --ip6 "fd71:8::${suffix}" "${project}-warp" "${project}-${role}"
  docker exec "${project}-${role}" python /app/routing.py "setup-${role}"
done
docker exec -d "${project}-tools" sh -c 'python -u /app/routing.py observe >/tmp/observer.log 2>&1'
docker create --name "${project}-router" --network "container:${project}-tools" \
  "$router_image" /config/router.yaml >/dev/null
docker cp router.yaml "${project}-router:/config/router.yaml"
docker start "${project}-router" >/dev/null

ready=0
for _ in $(seq 1 100); do
  if docker exec "${project}-tools" test -f /tmp/ready; then ready=1; break; fi
  sleep 0.1
done
[ "$ready" = 1 ] || { echo 'backend/capture/router readiness timed out' >&2; exit 1; }
client_rc=0
docker exec "${project}-client" python -u /app/routing.py client || client_rc=$?
# Stop capture after the client has finished; inspect flushed pcaps, not a timed sample.
docker exec "${project}-tools" touch /tmp/done
finished=0
for _ in $(seq 1 100); do
  if docker exec "${project}-tools" test -f /tmp/finished; then finished=1; break; fi
  sleep 0.1
done
[ "$finished" = 1 ] || { echo 'capture shutdown timed out' >&2; exit 1; }
docker exec "${project}-tools" python /app/routing.py check
[ "$client_rc" = 0 ]
echo 'IPv6 routing e2e passed (no fwmark)'
