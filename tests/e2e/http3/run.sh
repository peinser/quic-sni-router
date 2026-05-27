#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

project="qsr-http3-e2e"
network="${project}_e2e"
router_image="${project}-router:latest"
http3_image="${project}-http3:latest"

cleanup() {
  docker rm -f "${project}-client" "${project}-router" "${project}-rvr-a" "${project}-rvr-b" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
}

dump_logs() {
  docker logs "${project}-router" >&2 2>/dev/null || true
  docker logs "${project}-rvr-a" >&2 2>/dev/null || true
  docker logs "${project}-rvr-b" >&2 2>/dev/null || true
  docker logs "${project}-client" >&2 2>/dev/null || true
}
trap 'rc=$?; if [ ${rc} -ne 0 ]; then dump_logs; fi; cleanup' EXIT

cleanup

docker build -t "${router_image}" -f ../../../docker/Dockerfile --target e2e ../../..
docker build -t "${http3_image}" -f Dockerfile .

docker network create "${network}" >/dev/null

docker run -d --name "${project}-rvr-a" --network "${network}" --network-alias rvr-a \
  "${http3_image}" python /app/http3_backend.py --name rvr-a --hostname rvr-a.flightdeck.test --port 8443 >/dev/null
docker run -d --name "${project}-rvr-b" --network "${network}" --network-alias rvr-b \
  "${http3_image}" python /app/http3_backend.py --name rvr-b --hostname rvr-b.flightdeck.test --port 8444 >/dev/null
docker run -d --name "${project}-router" --network "${network}" \
  --network-alias rvr-a.flightdeck.test --network-alias rvr-b.flightdeck.test \
  "${router_image}" /config/router.yaml >/dev/null

router_ip=""
for _ in $(seq 1 20); do
  router_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${project}-router" 2>/dev/null || true)"
  if [ -n "${router_ip}" ]; then
    break
  fi
  sleep 0.25
done
if [ -z "${router_ip}" ]; then
  echo "router container did not receive an IPv4 address" >&2
  dump_logs
  exit 1
fi

docker run --name "${project}-client" --network "${network}" \
  --add-host "rvr-a.flightdeck.test:${router_ip}" \
  --add-host "rvr-b.flightdeck.test:${router_ip}" \
  "${http3_image}" python /app/http3_client.py --router-port 443
