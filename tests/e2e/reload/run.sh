#!/usr/bin/env bash
#
# Hot-reload e2e: bring up the router with one route, rewrite /config/router.yaml
# inside the running container with a different route set, assert inotify drove
# a reload and the new routes work (and pre-existing ones still do).
#
# Layout choices:
#   - Bake initial.yaml into a thin per-test image so the router has a valid
#     config at startup, then use `docker cp` to swap in updated.yaml live.
#     `docker cp` works in all docker environments (no bind-mount restrictions)
#     and exercises a file-replace pattern similar to a Kubernetes ConfigMap
#     update — both produce a fresh-inode write that fires inotify on /config.
#   - Reuse the http3 e2e backend image; only the entry point and config
#     differ.
#   - Bind-mount reload_client.py into the http3 image rather than baking
#     it in, so iteration doesn't require an image rebuild.
set -euo pipefail

cd "$(dirname "$0")"
here="$(pwd)"

project="qsr-reload-e2e"
network="${project}_net"
router_base_image="${project}-router:latest"
router_initial_image="${project}-router-initial:latest"
http3_image="qsr-http3-e2e-http3:latest" # shared with tests/e2e/http3
reload_client_image="${project}-client:latest"
sleep_for_reload="${QSR_RELOAD_WAIT_SECONDS:-2}"

cleanup() {
  docker rm -f \
    "${project}-router" \
    "${project}-rvr-a" \
    "${project}-rvr-b" \
    "${project}-client-1" \
    "${project}-client-2" \
    "${project}-client-3" \
    "${project}-client-4" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
}
dump_logs() {
  echo "--- router logs ---" >&2
  docker logs "${project}-router" >&2 2>/dev/null || true
  echo "--- rvr-a logs ---" >&2
  docker logs "${project}-rvr-a" >&2 2>/dev/null || true
  echo "--- rvr-b logs ---" >&2
  docker logs "${project}-rvr-b" >&2 2>/dev/null || true
}
trap 'rc=$?; if [ ${rc} -ne 0 ]; then dump_logs; fi; cleanup' EXIT

cleanup

# Build images. Router uses production target + a thin overlay that bakes the
# initial config at /config/router.yaml. Reload happens via `docker cp`.
docker build -t "${router_base_image}" -f ../../../docker/Dockerfile --target production ../../..
docker build -t "${router_initial_image}" -f - . <<EOF
FROM ${router_base_image}
COPY initial.yaml /config/router.yaml
EOF
if ! docker image inspect "${http3_image}" >/dev/null 2>&1; then
  docker build -t "${http3_image}" -f ../http3/Dockerfile ../http3
fi

# Bake reload_client.py on top of the shared http3 image so we don't have to
# bind-mount it (Docker Desktop has bind-mount path restrictions).
docker build -t "${reload_client_image}" -f - . <<EOF
FROM ${http3_image}
COPY reload_client.py /app/reload_client.py
EOF

docker network create "${network}" >/dev/null

docker run -d --name "${project}-rvr-a" --network "${network}" --network-alias rvr-a \
  "${http3_image}" python /app/http3_backend.py --name rvr-a --hostname rvr-a.flightdeck.test --port 8443 >/dev/null
docker run -d --name "${project}-rvr-b" --network "${network}" --network-alias rvr-b \
  "${http3_image}" python /app/http3_backend.py --name rvr-b --hostname rvr-b.flightdeck.test --port 8444 >/dev/null

docker run -d --name "${project}-router" --network "${network}" \
  --network-alias rvr-a.flightdeck.test \
  --network-alias rvr-b.flightdeck.test \
  "${router_initial_image}" /config/router.yaml >/dev/null

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
  exit 1
fi

run_client() {
  # $1 sni; $2 ... extra args
  local sni="$1"
  shift
  docker run --rm --network "${network}" \
    --add-host "rvr-a.flightdeck.test:${router_ip}" \
    --add-host "rvr-b.flightdeck.test:${router_ip}" \
    "${reload_client_image}" python /app/reload_client.py \
    --host "${sni}" --sni "${sni}" "$@"
}

echo "[phase 1] initial config — rvr-a should work, rvr-b should NOT route"
run_client rvr-a.flightdeck.test --expected "hello from rvr-a"$'\n'
run_client rvr-b.flightdeck.test --expect-fail --timeout 3

echo "[phase 2] swap config in-place (docker cp) — wait ${sleep_for_reload}s for inotify-driven reload"
docker cp updated.yaml "${project}-router:/config/router.yaml"
sleep "${sleep_for_reload}"

echo "[phase 3] reloaded config — both rvr-a (unchanged) and rvr-b (added) must work"
run_client rvr-b.flightdeck.test --expected "hello from rvr-b"$'\n'
run_client rvr-a.flightdeck.test --expected "hello from rvr-a"$'\n'

echo "[phase 4] verify router logged the reload"
if ! docker logs "${project}-router" 2>&1 | grep -q "^reload: ok"; then
  echo "router did not log 'reload: ok' — inotify path may not have fired" >&2
  exit 1
fi

echo "RELOAD E2E PASSED"
