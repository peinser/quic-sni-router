#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

project="qsr-reverse-e2e"
network="${project}_e2e"
router_image="${project}-router:latest"
http3_image="${project}-http3:latest"

cleanup() {
  docker rm -f "${project}-client" "${project}-router" "${project}-backend" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
}

dump_logs() {
  docker logs "${project}-router" >&2 2>/dev/null || true
  docker logs "${project}-backend" >&2 2>/dev/null || true
  docker logs "${project}-client" >&2 2>/dev/null || true
}
trap cleanup EXIT

cleanup

docker build -t "${router_image}" -f ../../../docker/Dockerfile --target e2e ../../..
docker build -t "${http3_image}" -f ../http3/Dockerfile ../http3

docker network create "${network}" >/dev/null

docker run -d --name "${project}-backend" --network "${network}" --network-alias marker-backend \
  "${http3_image}" python /app/marker_backend.py --port 8443 >/dev/null
docker create --name "${project}-router" --network "${network}" --network-alias reverse.flightdeck.test \
  "${router_image}" /config/router.yaml >/dev/null
docker cp router.yaml "${project}-router:/config/router.yaml"
docker start "${project}-router" >/dev/null

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

if ! docker run --name "${project}-client" --network "${network}" \
  "${http3_image}" python /app/reverse_tuple_client.py --router-host "${router_ip}" --router-port 443; then
  dump_logs
  exit 1
fi
