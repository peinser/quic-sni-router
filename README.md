# quic-sni-router

[![CI](https://github.com/Peinser/quic-sni-router/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/Peinser/quic-sni-router/actions/workflows/ci.yaml)
[![Image](https://github.com/Peinser/quic-sni-router/actions/workflows/image.yaml/badge.svg?branch=main)](https://github.com/Peinser/quic-sni-router/actions/workflows/image.yaml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status: pre-1.0](https://img.shields.io/badge/status-pre--1.0-orange.svg)](ROADMAP.md)

A small QUIC SNI router for pod-terminated mTLS and HTTP/3 services.

> **Status: pre-1.0 / MVP.** Production-shape: real CI, sanitizers, fuzz harnesses, RFC-vector tests, Docker e2e for v1 + v2 and hot reload, hardened Helm chart. But pre-1.0 means we may break wire-adjacent behaviour or config-file semantics between 0.x releases without a major bump. Track planned changes in [ROADMAP.md](ROADMAP.md) and breaking changes in [CHANGELOG.md](CHANGELOG.md).

Goal:

```text
client UDP 443 -> quic-sni-router -> FlightDeck pod UDP 8443
```

`quic-sni-router` receives UDP QUIC packets, decrypts only QUIC v1 (RFC 9000) and QUIC v2 (RFC 9369) Initial packets far enough to read TLS ClientHello SNI, picks a configured backend, and then forwards original datagrams unchanged. Backends keep terminating TLS/mTLS; the router does not load certificates or private keys.

Current status is an MVP dataplane with QUIC v1 + v2 Initial deprotection via OpenSSL libcrypto, CRYPTO frame extraction, TLS ClientHello SNI extraction, exact-SNI route lookup, UDP forwarding, session pinning, CI, fuzz harnesses, Docker e2e tests, and devcontainer setup.

The dataplane pre-resolves configured backend hosts before entering the packet loop and maintains tuple plus observed CID session aliases. NAT rebinding can recover via learned long-header or short-header CIDs on a best-effort basis. Linux builds use `io_uring` multishot `recvmsg` plus `sendmmsg`; other platforms use a portable `recvfrom`/`sendto` loop.

## WAN-facing caveats

Read this before exposing the router to the public internet:

- **Backend isolation.** Backends should be on a non-routable / cluster-internal network. The router learns a `backend_ip:port` reverse mapping; if an attacker can spoof packets *with that source address* to UDP/443, the router will forward them toward the associated client. QUIC's own AEAD makes this an annoyance rather than a takeover, but the safer posture is to make backends unreachable from the WAN.
- **Anti-amplification.** The router drops Initial datagrams shorter than 1200 bytes from unknown sources (RFC 9000 §14.1), so it cannot be turned into a UDP amplifier. Add upstream BCP 38 / uRPF to block spoofed sources entirely.
- **CPU DoS.** There is no in-process per-source rate limit. Combine with eBPF/nftables/cloud LB rate limiting before exposing to untrusted networks.
- **Session table.** Provision `maxSessions` for `expected_connections_per_second × idleTimeout_seconds × ~5` — each new QUIC connection creates roughly 5 table entries (forward tuple, reverse tuple, DCID alias, SCID alias, DCID+SCID pair). At 1000 conn/s with the default 60s `idleTimeout`, that's ~300k. When the cap is hit, the oldest entry by `last_seen` is evicted; if you're under-provisioned you'll see active connections break mid-flight.
- **Single-threaded.** Each router process pins to one core. Run multiple processes; `SO_REUSEPORT` is set automatically so the kernel hashes flows across them.
- **DNS is one-shot.** Backends are resolved at startup AND on every hot reload (see below). To pick up a backend IP change without a config edit, restart the process.
- **Hot reload.** The directory containing `config.yaml` is watched via `inotify`. Editing the file or having Kubernetes swap the ConfigMap symlink triggers re-parse + DNS re-resolve + atomic swap, with no packet loss. Sessions whose backend disappeared from the new config are evicted (hard cutover); sessions to surviving backends keep going. `listen.udp` and `sessions.maxSessions` changes are logged and ignored until restart.
- **ECH-aware behaviour.** With Encrypted ClientHello, the router sees the OUTER ClientHello's cover hostname (e.g. `cloudflare-ech.com`) — not the real inner hostname, which is encrypted. We route by whatever's in the outer SNI, so ECH-using clients work iff the cover hostname is a configured route; otherwise their packets drop like any other unrouted SNI. The router can never see the inner hostname without terminating TLS (we don't).
- **QUIC versions.** v1 (RFC 9000) and v2 (RFC 9369) are accepted. Any other version returns `UNSUPPORTED` at the parser and the packet is dropped (clients will fall back via version negotiation).

See [docs/threat-model.md](docs/threat-model.md) for the full threat model.

## Build

```sh
make build
make test
make test-e2e
make sanitize
make fuzz-smoke
make benchmark
```

`make test-e2e` uses Docker Compose to start two mock HTTP/3 backends and verifies that SNI routes to both through the router. It requires Docker and network access to build the Python/aioquic test image.

## Run

```sh
quic-sni-router config.yaml
```

Build the production image from `docker/Dockerfile`:

```sh
make docker-build
```

Run it with the routing config mounted at the default path:

```sh
docker run --rm -p 443:443/udp -v ./router.yaml:/config/router.yaml:ro \
  harbor.peinser.com/uas/quic-sni-router:dev
```

The runtime image exposes `443/udp`, runs as the non-root `qsr` user, and defaults to `/config/router.yaml`. It does not contain TLS private keys and does not terminate backend TLS or mTLS.

## Kubernetes

### Helm (recommended)

```sh
helm install qsr oci://harbor.peinser.com/library/charts/quic-sni-router \
  --version <chart-version> \
  --namespace tower-system --create-namespace \
  -f values.yaml
```

The chart lives in [charts/quic-sni-router/](charts/quic-sni-router/) and is published to `oci://harbor.peinser.com/library/charts/quic-sni-router` on every push to `main` (see [.github/workflows/helm.yaml](.github/workflows/helm.yaml)). Defaults: 2-replica `Deployment`, `LoadBalancer` Service (`externalTrafficPolicy: Cluster`; switch to `Local` if you want real client source IPs), `PodDisruptionBudget`, hardened pod + container security context, `automountServiceAccountToken: false`, no CPU limit (avoids CFS throttling on the UDP dataplane), and `inotify`-driven hot reload of the `ConfigMap` (no pod restart on `helm upgrade`).

See [charts/quic-sni-router/README.md](charts/quic-sni-router/README.md) for the full values reference, schema, and WAN deployment checklist.

### Raw manifests

If you don't use Helm, mount the router config as a ConfigMap at `/config/router.yaml` and expose UDP/443 with a `LoadBalancer`, `NodePort`, host-networked DaemonSet, or equivalent cluster edge pattern.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: quic-sni-router
data:
  router.yaml: |
    listen:
      udp: ":443"
    routes:
      rvr-a.flightdeck.tower.peinser.com:
        host: flightdeck-rvr-a.tower-system.svc.cluster.local
        port: 8443
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: quic-sni-router
spec:
  selector:
    matchLabels:
      app: quic-sni-router
  template:
    metadata:
      labels:
        app: quic-sni-router
    spec:
      containers:
      - name: router
        image: harbor.peinser.com/library/quic-sni-router:sha-<revision>
        ports:
        - containerPort: 443
          protocol: UDP
        volumeMounts:
        - name: config
          mountPath: /config/router.yaml
          subPath: router.yaml
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: quic-sni-router
```

Backend services should listen for QUIC on their configured UDP port and keep their own certificates, client CA policy, and mTLS enforcement. The router forwards original QUIC datagrams unchanged after SNI-based backend selection.

If a route points at a normal Kubernetes `Service`, Kubernetes may load-balance UDP traffic across the Service endpoints. QUIC requires all datagrams for a connection to reach the same backend pod that owns that QUIC connection state. Use a stable per-pod endpoint, a headless Service with explicit pod DNS names, or configure Service affinity when routing to a Service:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: flightdeck-rvr-a
  namespace: tower-system
spec:
  type: ClusterIP
  sessionAffinity: ClientIP
  sessionAffinityConfig:
    clientIP:
      timeoutSeconds: 10800
  selector:
    app: flightdeck-rvr-a
  ports:
  - name: quic
    protocol: UDP
    port: 8443
    targetPort: 8443
```

`sessionAffinity: ClientIP` can keep UDP packets from one router pod pinned to one backend pod, but it is not QUIC-aware and may collapse balancing if many client sessions arrive through the same router pod IP. For predictable per-connection distribution, prefer routing directly to pod endpoints or placing a QUIC-aware load balancer behind the router.

## Performance Builds

Production containers configure CMake with `-DCMAKE_BUILD_TYPE=Release` and build with `clang`. For Clang/GCC this already enables the toolchain's Release defaults, typically `-O3 -DNDEBUG`. Linux builds use an `io_uring` multishot receive loop plus `sendmmsg` send batching.

Useful build toggles:

- `-DQSR_ENABLE_SANITIZERS=ON`: ASAN/UBSAN test build.
- `-DQSR_BUILD_FUZZERS=ON`: libFuzzer harnesses.
- `-DQSR_BUILD_BENCHMARKS=ON`: synthetic dataplane benchmarks.
- `-DQSR_CPU_TARGET=native`: tune Release builds for the local CPU.
- `-DQSR_CPU_TARGET=znver3` or `znver4`: tune Release builds for a known Ryzen generation.
- `-DQSR_ENABLE_LTO=ON`: enable Release interprocedural optimization when supported by the compiler/linker.
- `-DQSR_ENABLE_PACKET_DEBUG=ON`: compile packet decision logging support. Published images use a separate `-debug` tag for this and still require `QSR_DEBUG_PACKETS=1` at runtime before logging packets.

For Ryzen-only hosts, benchmark the portable Release build against a native-tuned build:

```sh
make benchmark
make benchmark-native
```

For a host-specific container image on the same Ryzen fleet, build with:

```sh
make docker-build QSR_CPU_TARGET=native QSR_ENABLE_LTO=ON
```

Use `native` only when the image will run on CPUs compatible with the build host. For published portable images, leave `QSR_CPU_TARGET` empty. The image workflow publishes paired multi-arch manifests (`linux/amd64` and `linux/arm64`): the default tag has packet debug logging compiled out, and the matching `-debug` tag compiles it in for production diagnosis.

## Config

```yaml
listen:
  udp: ":443"
sessions:
  idleTimeout: 60s         # 1..86400, applied with CLOCK_MONOTONIC
  maxSessions: 100000      # session-table entries; one QUIC connection uses multiple aliases
routes:
  rvr-a.flightdeck.tower.peinser.com:
    host: flightdeck-rvr-a.tower-system.svc.cluster.local
    port: 8443             # 1..65535
```

The parser uses [libyaml](https://github.com/yaml/libyaml) (YAML 1.1) so the full input surface — block and flow style, single- and double-quoted scalars, multi-line scalars, comments anywhere, anchors and aliases — is accepted. The schema, however, is intentionally strict:

- Top-level keys must be one of `listen`, `sessions`, `routes`. An unknown key (typo) is rejected rather than silently ignored.
- `listen.udp`, `sessions.idleTimeout` (optional `s` suffix, range `1..86400`), `sessions.maxSessions` (range `1..1000000`) are scalar.
- Each route has exactly `host:` and `port:` (range `1..65535`); other per-route keys are rejected.
- SNI keys are normalized to lower-case ASCII DNS names and label-validated (no leading hyphen, no empty labels, max 255 chars).
- Empty file = use defaults.

More examples are in `docs/examples.md`, including devcontainer backend services and route/session lookup design notes.

See `examples/mtls-backends/` for a Docker Compose demo with two HTTP/3 mTLS backends routed by SNI.

## Testing

- `make test`: C unit tests.
- `make sanitize`: C unit tests under ASAN/UBSAN.
- `make fuzz-smoke`: short libFuzzer smoke tests where libFuzzer is available.
- `make test-e2e`: Docker HTTP/3 SNI routing test using aioquic mock backends (covers v1 and v2).
- `make test-e2e-reload`: Docker hot-reload test — start with one route, `docker cp` a new config in, assert inotify drove a reload and the new route works.
- `make test-loadtest`: Docker correctness-under-load test using many fresh QUIC handshakes. Set `QSR_LOADTEST_DIRECT=1` to bypass the router for baseline comparison, or `QSR_LOADTEST_PERSISTENT=1` to reuse one HTTP/3 session per worker.
- `make benchmark`: synthetic CPU benchmarks for route lookup, session lookup, and CRYPTO frame extraction.

## References

- `dlundquist/sniproxy` for separation of listener, parser, route table, and forwarding responsibilities.
- `AGWA/snid` for a minimal SNI demux philosophy and backend safety constraints.
- `HyBuildNet/quic-relay` for a Go QUIC reverse proxy with SNI routing, handler-chain extensibility, load balancing, hot reload, and optional QUIC TLS termination for Hytale protocol inspection.
- See `docs/inspirations.md` for what is and is not portable from TCP SNI proxies.

## License

Copyright 2026 Peinser BV.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text and [NOTICE](NOTICE) for third-party attributions.
