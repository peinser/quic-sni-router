#!/usr/bin/env bash
#
# Loadtest e2e: 10 aioquic HTTP/3 backends behind the router, sustained
# concurrent connection load via tests/e2e/loadtest/loadtest_client.py.
# Pass criteria: zero misrouted responses AND success rate >= threshold
# (default 95%). Misroute is always a hard fail regardless of threshold —
# a router that hands the wrong backend's body to a client under load is
# fundamentally broken, not just slow.
#
# Tunables (env vars):
#   QSR_LOADTEST_DURATION    seconds, default 30
#   QSR_LOADTEST_CONCURRENCY workers, default 10
#   QSR_LOADTEST_THRESHOLD   0..1, default 0.95
#   QSR_LOADTEST_BACKENDS    default 10
#   QSR_LOADTEST_DIRECT      bypass router and hit backends directly, default 0
#   QSR_LOADTEST_PERSISTENT  reuse one HTTP/3 session per worker, default 0
set -euo pipefail

cd "$(dirname "$0")"
here="$(pwd)"

project="qsr-loadtest"
network="${project}_net"
router_base_image="${project}-router-base:latest"
router_initial_image="${project}-router:latest"
http3_image="qsr-http3-e2e-http3:latest"      # shared with tests/e2e/http3
loadtest_image="${project}-client:latest"

duration="${QSR_LOADTEST_DURATION:-30}"
# 10 workers across 10 backends = 1 concurrent per backend, comfortably
# within single-threaded Python aioquic's sustained throughput. Higher
# concurrency adds aioquic tail-latency timeouts that aren't router bugs;
# raise it only if you also raise n_backends.
concurrency="${QSR_LOADTEST_CONCURRENCY:-10}"
threshold="${QSR_LOADTEST_THRESHOLD:-0.95}"
n_backends="${QSR_LOADTEST_BACKENDS:-10}"
direct="${QSR_LOADTEST_DIRECT:-0}"
persistent="${QSR_LOADTEST_PERSISTENT:-0}"
backend_port=8443
client_script="loadtest_client.py"
if [ "${persistent}" = "1" ]; then
  client_script="persistent_loadtest_client.py"
fi

cleanup() {
  # Wildcard cleanup catches all per-backend containers and the client.
  ids="$(docker ps -a --filter "name=^${project}-" -q 2>/dev/null || true)"
  if [ -n "${ids}" ]; then
    docker rm -f ${ids} >/dev/null 2>&1 || true
  fi
  docker network rm "${network}" >/dev/null 2>&1 || true
}
dump_logs() {
  echo "--- router logs ---" >&2
  docker logs "${project}-router" >&2 2>/dev/null || true
  for i in $(seq 1 "${n_backends}"); do
    echo "--- rvr-${i} logs (tail) ---" >&2
    docker logs "${project}-rvr-${i}" 2>&1 | tail -10 >&2 || true
  done
}
trap 'rc=$?; if [ ${rc} -ne 0 ]; then dump_logs; fi; cleanup' EXIT

cleanup

# Generate the router config with N routes (rvr-1..rvr-N on ports 8444..8443+N)
config_dir="$(mktemp -d -t qsr-loadtest-XXXXXX)"
chmod 0755 "${config_dir}"
{
  echo "listen:"
  echo "  udp: \":8443\""
  echo "sessions:"
  echo "  idleTimeout: 60s"
  # Generous cap: each new connection creates ~5 table entries (forward
  # tuple, reverse tuple, dcid alias, scid alias, dcid+scid pair). A long
  # loadtest run can otherwise hit eviction and break active sessions.
  echo "  maxSessions: 1000000"
  echo "routes:"
  for i in $(seq 1 "${n_backends}"); do
    echo "  rvr-${i}.flightdeck.test:"
    echo "    host: rvr-${i}"
    echo "    port: ${backend_port}"
  done
} > "${config_dir}/router.yaml"
chmod 0644 "${config_dir}/router.yaml"

# Build images. Router uses the production target (no baked config); we
# overlay the generated config in a tiny derived image — same trick as the
# reload e2e, which sidesteps Docker Desktop's bind-mount restrictions.
docker build -t "${router_base_image}" -f ../../../docker/Dockerfile --target production ../../..
cp "${config_dir}/router.yaml" router.yaml
docker build -t "${router_initial_image}" -f - . <<EOF
FROM ${router_base_image}
COPY router.yaml /config/router.yaml
EOF
rm router.yaml

if ! docker image inspect "${http3_image}" >/dev/null 2>&1; then
  docker build -t "${http3_image}" -f ../http3/Dockerfile ../http3
fi
docker build -t "${loadtest_image}" -f - . <<EOF
FROM ${http3_image}
COPY loadtest_client.py /app/loadtest_client.py
COPY persistent_loadtest_client.py /app/persistent_loadtest_client.py
EOF

docker network create "${network}" >/dev/null

# Spin up N backends. Each listens on its own port and serves a canonical
# "hello from rvr-<i>" response; the loadtest client matches the body
# prefix to verify correct routing.
for i in $(seq 1 "${n_backends}"); do
  name="rvr-${i}"
  sni="${name}.flightdeck.test"
  docker run -d --name "${project}-${name}" \
    --network "${network}" --network-alias "${name}" --network-alias "${sni}" \
    "${http3_image}" python /app/http3_backend.py \
      --name "${name}" --hostname "${sni}" --port "${backend_port}" >/dev/null
done

add_hosts=()
if [ "${direct}" != "1" ]; then
  # Router: it needs to resolve every backend's --hostname alias on startup.
  docker run -d --name "${project}-router" \
    --network "${network}" --network-alias "router" \
    "${router_initial_image}" /config/router.yaml >/dev/null

  # Wait for router to come up and learn its IP.
  router_ip=""
  for _ in $(seq 1 20); do
    router_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${project}-router" 2>/dev/null || true)"
    [ -n "${router_ip}" ] && break
    sleep 0.25
  done
  if [ -z "${router_ip}" ]; then
    echo "router container did not receive an IPv4 address" >&2
    exit 1
  fi

  # Client: map every SNI to the router's IP via --add-host so name resolution
  # from inside the client container picks the router, not the actual backends.
  for i in $(seq 1 "${n_backends}"); do
    add_hosts+=("--add-host" "rvr-${i}.flightdeck.test:${router_ip}")
  done
fi

sni_list=""
for i in $(seq 1 "${n_backends}"); do
  sni="rvr-${i}.flightdeck.test"
  if [ -z "${sni_list}" ]; then
    sni_list="${sni}"
  else
    sni_list="${sni_list},${sni}"
  fi
done

# Warmup: aioquic backends self-generate a TLS cert on first request via an
# `openssl req` subprocess (~few hundred ms each). Without a warmup, the
# first second of the real run sees a flood of TimeoutErrors and can push
# the success rate below threshold. Do one short parallel pass — same
# loadtest tool, low concurrency, ignored result.
echo "loadtest: warming up ${n_backends} backends (~3s)"
docker run --rm --network "${network}" \
  "${add_hosts[@]}" \
  "${loadtest_image}" \
  python "/app/${client_script}" \
    --port "${backend_port}" --snis "${sni_list}" \
    --concurrency "${n_backends}" --duration 3 \
    --pass-threshold 0 >/dev/null 2>&1 || true

if [ "${direct}" = "1" ]; then
  echo "loadtest: starting ${concurrency} workers x ${duration}s directly against ${n_backends} backends"
else
  echo "loadtest: starting ${concurrency} workers x ${duration}s through router against ${n_backends} backends"
fi
docker run --rm --name "${project}-client" \
  --network "${network}" \
  "${add_hosts[@]}" \
  "${loadtest_image}" \
  python "/app/${client_script}" \
    --port "${backend_port}" \
    --snis "${sni_list}" \
    --concurrency "${concurrency}" \
    --duration "${duration}" \
    --pass-threshold "${threshold}"
