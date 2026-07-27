# quic-sni-router

[![CI](https://github.com/Peinser/quic-sni-router/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/Peinser/quic-sni-router/actions/workflows/ci.yaml)
[![Image](https://github.com/Peinser/quic-sni-router/actions/workflows/image.yaml/badge.svg?branch=main)](https://github.com/Peinser/quic-sni-router/actions/workflows/image.yaml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status: pre-1.0](https://img.shields.io/badge/status-pre--1.0-orange.svg)](ROADMAP.md)

Route QUIC traffic to different backends based on the TLS SNI, without terminating TLS.

```text
client UDP 443 -> quic-sni-router -> backend pod UDP 8443
```

The router reads incoming UDP datagrams, decrypts just enough of a QUIC Initial packet to recover the TLS ClientHello, extracts the SNI, looks up a backend, and forwards the original datagrams byte-for-byte. It never loads a certificate or a private key. Backends keep terminating their own TLS or mTLS, and they see a genuine QUIC handshake rather than a re-originated one.

Both QUIC v1 (RFC 9000) and v2 (RFC 9369) Initials are supported. Anything else is dropped at the parser, which makes clients fall back through version negotiation.

## Get the image

Images are published to [GitHub Container Registry](https://github.com/peinser/quic-sni-router/pkgs/container/quic-sni-router) as multi-arch manifests covering `linux/amd64` and `linux/arm64`. No authentication needed.

```sh
docker pull ghcr.io/peinser/quic-sni-router:latest
```

`latest` tracks the head of `main`. For anything you deploy, pin the immutable `<version>-<sha>` tag that build also published:

```sh
docker pull ghcr.io/peinser/quic-sni-router:0.1.0-530ab14
```

To see which tags exist, browse the [packages page](https://github.com/peinser/quic-sni-router/pkgs/container/quic-sni-router) or ask the registry directly:

```sh
crane ls ghcr.io/peinser/quic-sni-router                             # every tag
docker buildx imagetools inspect ghcr.io/peinser/quic-sni-router:latest   # what latest resolves to
```

Every tag has a matching `-debug` variant (`:latest-debug`, `:0.1.0-530ab14-debug`). It is the same Release build with packet decision logging compiled in, still gated behind `QSR_DEBUG_PACKETS=1` at runtime, so it costs nothing until you switch it on.

## Status

Pre-1.0. [ROADMAP.md](ROADMAP.md) has what is planned, [CHANGELOG.md](CHANGELOG.md) has what already changed.

## How forwarding works

Each client tuple gets its own upstream UDP socket toward its backend. The backend therefore sees one router source port per client, and return traffic demultiplexes purely by which socket received it, with no table lookup at all in that direction. That is what makes concurrent connections to the same backend work, including clients that use zero-length connection IDs (Chrome does) or rotate them after the handshake.

Alongside the flows, the router keeps a session table of connection ID aliases learned from long-header packets in both directions. Those aliases are what let a NAT rebind recover: a client that reappears from a new source port is matched by its DCID instead of its tuple. It is best-effort, not guaranteed.

Backend hostnames are resolved once before the packet loop starts, and again on every config reload. On Linux the loop uses `epoll` with `recvmmsg`/`sendmmsg` for batched I/O; elsewhere it falls back to `poll` with `recvfrom`/`sendto`.

## Before you put this on the internet

- **Keep backends off the WAN.** Return traffic is accepted on per-flow ephemeral ports, so an attacker who can both spoof a backend's source address and guess a live flow's port can inject packets toward that client. QUIC's AEAD makes that a nuisance rather than a compromise, but an unroutable backend network removes the problem entirely.
- **Amplification is handled.** Initial datagrams shorter than 1200 bytes from unknown sources are dropped per RFC 9000 §14.1, so the router cannot be used as a UDP amplifier. BCP 38 / uRPF upstream is still worth having.
- **Rate limiting is not.** There is no per-source limit in the process. Put eBPF, nftables, or a cloud load balancer in front of it before exposing it to untrusted networks.
- **Size the session table.** A new QUIC connection creates roughly four to five entries (forward tuple, DCID alias, server SCID alias, DCID+SCID pair, plus a reverse tuple once a rebind happens). Budget `connections_per_second × idleTimeout_seconds × 5`; at 1000 conn/s with the default 60s timeout that is about 300k. When `maxSessions` is reached the least recently seen entry is evicted, which breaks live connections if you are under-provisioned.
- **Size the file descriptors.** One UDP socket per concurrent flow, with the flow table capped at `maxSessions / 4`. The process raises `RLIMIT_NOFILE` to its hard limit at startup and warns if that is still not enough; past the cap, the oldest flow is recycled. Set the container's `ulimit -n` above your expected concurrency.
- **One core per process.** The dataplane is single-threaded on purpose. Run several processes instead: `SO_REUSEPORT` is set automatically and the kernel hashes flows across them.
- **ECH shows you the cover name.** With Encrypted ClientHello the router only ever sees the outer SNI (`cloudflare-ech.com` and friends). Routing works if that cover name is a configured route, and drops otherwise. The inner name is unreachable without terminating TLS, which is exactly what this thing refuses to do.

[docs/threat-model.md](docs/threat-model.md) has the full analysis.

## Build

```sh
make build          # router and tests
make test           # unit tests
make sanitize       # unit tests under ASAN/UBSAN
make fuzz-smoke     # short libFuzzer runs over the parsers
make benchmark      # synthetic route/session/parser benchmarks
make test-e2e       # Docker HTTP/3 routing test
```

Dependencies are OpenSSL libcrypto, libyaml, CMake 3.25+, and a C23 compiler. The end-to-end targets need Docker and outbound network access to build the aioquic test image. [.devcontainer/](.devcontainer/) has a container with everything preinstalled.

## Run

```sh
quic-sni-router config.yaml
```

Or from the published image:

```sh
docker run --rm -p 443:443/udp -v ./router.yaml:/config/router.yaml:ro \
  ghcr.io/peinser/quic-sni-router:latest
```

The runtime image exposes `443/udp`, runs as the non-root `qsr` user, and reads `/config/router.yaml` by default. To build it yourself:

```sh
make docker-build
```

## Config

```yaml
listen:
  udp: ":443"
sessions:
  idleTimeout: 60s         # 1..86400, measured on CLOCK_MONOTONIC
  maxSessions: 100000      # table entries, not connections; see the sizing note above
routes:
  rvr-a.flightdeck.tower.peinser.com:
    host: flightdeck-rvr-a.tower-system.svc.cluster.local
    port: 8443             # 1..65535
logging:
  connections: false       # one stderr line per backend flow open and close
```

Parsing is done by [libyaml](https://github.com/yaml/libyaml), so the whole YAML 1.1 surface is accepted: block and flow style, quoted and multi-line scalars, comments, anchors, aliases. The schema on top of it is deliberately unforgiving:

- The only top-level keys are `listen`, `sessions`, `routes`, `cidEncoding`, and `logging`. Anything else is an error rather than a silently ignored typo.
- Each route takes exactly `host` and `port`. Extra keys are rejected.
- SNI keys are lower-cased and validated as DNS names: no empty labels, no leading hyphens, 255 characters max.
- An empty file means defaults.

With `logging.connections: true` you get one line when a flow opens and one when it closes:

```text
conn: open src=203.0.113.7:51820 sni=rvr-a.example scid=8f2c01ab backend=10.0.4.12:8443
conn: close src=203.0.113.7:51820 sni=rvr-a.example reason=idle duration=63s
```

Close reasons are `idle`, `evicted`, `reload`, `shutdown`, `reroute`, and `error`. Nothing is logged per packet, so this is safe to leave on in production. Like the rest of the config, it is hot-reloadable.

### Hot reload

The directory holding `config.yaml` is watched with `inotify`. Editing the file, or Kubernetes swapping a ConfigMap symlink, triggers a re-parse, a DNS re-resolve, and an atomic swap with no packet loss. Sessions whose backend vanished from the new config are evicted; everything else keeps running. Changes to `listen.udp` and `sessions.maxSessions` are logged and ignored until restart.

One caveat: the reload's DNS resolution happens synchronously on the dataplane thread, so packets queue in the kernel buffer while `getaddrinfo` runs. That is sub-millisecond with IP literals or a healthy local resolver, but an unreachable DNS server can stall forwarding for its full timeout. Use IP backends or a local caching resolver if reload latency matters to you.

More examples are in [docs/examples.md](docs/examples.md), and [examples/mtls-backends/](examples/mtls-backends/) is a Compose demo with two HTTP/3 mTLS backends routed by SNI.

## Kubernetes

```sh
helm install qsr oci://harbor.peinser.com/library/charts/quic-sni-router \
  --version <chart-version> \
  --namespace tower-system --create-namespace \
  -f values.yaml
```

The chart is in [charts/quic-sni-router/](charts/quic-sni-router/) and is published on every push to `main`. It defaults to a 2-replica Deployment behind a `LoadBalancer` Service, a PodDisruptionBudget, hardened pod and container security contexts, `automountServiceAccountToken: false`, no CPU limit (CFS throttling and a UDP dataplane do not mix), and ConfigMap hot reload, so `helm upgrade` does not restart pods. Switch `externalTrafficPolicy` to `Local` if you need real client source addresses. The [chart README](charts/quic-sni-router/README.md) has the full values reference and a WAN deployment checklist.

Without Helm, mount the config as a ConfigMap at `/config/router.yaml` and expose UDP/443 however you normally reach the cluster edge:

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
        image: ghcr.io/peinser/quic-sni-router:<version>-<sha>
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

### Watch out for Service load balancing

QUIC needs every datagram of a connection to reach the pod that holds that connection's state. A plain `Service` will happily spread UDP across endpoints and break exactly that. Route to pod endpoints directly, use a headless Service with per-pod DNS names, or set affinity:

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

`sessionAffinity: ClientIP` pins packets from one router pod to one backend pod, but it is not QUIC-aware and collapses balancing when many client sessions arrive through the same router pod IP. Per-pod endpoints are the predictable choice.

## Build tuning

Published images are `-DCMAKE_BUILD_TYPE=Release` built with clang, which gets you `-O3 -DNDEBUG` and little else worth configuring. An earlier `io_uring` path was removed: its submit-then-wait-per-packet shape was strictly slower than batched `recvmmsg`/`sendmmsg`. See [docs/benchmarks.md](docs/benchmarks.md) for numbers.

| Option | Effect |
| --- | --- |
| `QSR_ENABLE_SANITIZERS=ON` | ASAN/UBSAN test build |
| `QSR_BUILD_FUZZERS=ON` | libFuzzer harnesses |
| `QSR_BUILD_BENCHMARKS=ON` | synthetic dataplane benchmarks |
| `QSR_CPU_TARGET=native` | tune Release for the build host's CPU |
| `QSR_CPU_TARGET=znver3` or `znver4` | tune Release for a known Ryzen generation |
| `QSR_ENABLE_LTO=ON` | interprocedural optimization, where the toolchain supports it |
| `QSR_ENABLE_PACKET_DEBUG=ON` | compile in packet decision logging |
| `BASE_IMAGE=<ref>` | container base image, defaults to `docker.io/library/ubuntu:24.04` |

To see whether CPU tuning buys you anything on a homogeneous fleet, compare:

```sh
make benchmark
make benchmark-native
```

and if it does, bake it in with `make docker-build QSR_CPU_TARGET=native QSR_ENABLE_LTO=ON`. Only do that when every host running the image is compatible with the build host. Published images leave `QSR_CPU_TARGET` empty.

## Tests

| Target | What it covers |
| --- | --- |
| `make test` | unit tests, including the RFC 9001 and RFC 9369 Initial-key vectors |
| `make sanitize` | the same tests under ASAN/UBSAN |
| `make fuzz-smoke` | short libFuzzer runs over the Initial, frame, and ClientHello parsers |
| `make test-e2e` | HTTP/3 SNI routing to two aioquic backends, v1 and v2 |
| `make test-e2e-flows` | per-flow upstream isolation |
| `make test-e2e-fragmented` | ClientHello split across out-of-order Initials |
| `make test-e2e-rebind` | NAT rebind on a connection aged past `idleTimeout` |
| `make test-e2e-idle` | backend idle timeout handling |
| `make test-e2e-reverse` | reverse-tuple routing of stale resets |
| `make test-e2e-reload` | inotify hot reload picks up a new route |
| `make test-loadtest` | 10 backends under sustained concurrent handshakes, asserting zero misroutes |

`make test-loadtest` takes `QSR_LOADTEST_DIRECT=1` to bypass the router for a baseline, and `QSR_LOADTEST_PERSISTENT=1` to reuse one HTTP/3 session per worker.

## Prior work

`dlundquist/sniproxy` for the separation of listener, parser, route table, and forwarder. `AGWA/snid` for a minimal SNI demux philosophy and its backend safety constraints. `HyBuildNet/quic-relay` for a Go take with handler chains, load balancing, and optional TLS termination. [docs/inspirations.md](docs/inspirations.md) covers what does and does not carry over from TCP SNI proxies.

## License

Copyright 2026 Peinser BV. Apache 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
