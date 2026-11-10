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

Both QUIC v1 (RFC 9000) and v2 (RFC 9369) Initials are supported. Unsupported versions are dropped; the router does not emit Version Negotiation packets, so clients must support a configured version or perform their own fallback.

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

**Compatibility limit: one backend per client UDP tuple.** Two independent QUIC connections sharing one client UDP socket cannot reliably reach different backends through the same router address. Routing the second connection to a different backend replaces the first connection's upstream socket; in ordinary SNI mode, subsequent short-header packets from either connection go to the latest backend. Encoded-CID modes can select the backend per packet but still replace that shared flow, so they do not remove this limitation. Use distinct client UDP sockets/source ports for cross-backend connections. Connections sharing a tuple and targeting the same backend can share the flow.

Alongside the flows, the router keeps a session table of connection ID aliases learned from long-header packets in both directions. Those aliases are what let a NAT rebind recover: a client that reappears from a new source port is matched by its DCID instead of its tuple. It is best-effort, not guaranteed.

Backend hostnames are resolved once before the packet loop starts, and again on every config reload. On Linux the loop uses `epoll` with `recvmmsg`/`sendmmsg` for batched I/O; elsewhere it falls back to `poll` with `recvfrom`/`sendto`.

## Before you put this on the internet

- **Keep backends private.** Connected upstream sockets accept return packets only from the configured backend endpoint. This filters unrelated sources; QUIC authentication and upstream anti-spoofing remain necessary against spoofed backend traffic.
- **Backends enforce anti-amplification.** The router drops unknown Initial datagrams shorter than 1200 bytes. This is a protocol minimum, not a no-amplification guarantee: a QUIC backend may send up to three times received bytes before address validation. Use BCP 38 / uRPF upstream.
- **Rate limiting is not.** There is no per-source limit in the process. Put eBPF, nftables, or a cloud load balancer in front of it before exposing it to untrusted networks.
- **Size the session table.** A new QUIC connection creates roughly four to five entries (forward tuple, DCID alias, server SCID alias, DCID+SCID pair, plus a reverse tuple once a rebind happens). Budget `connections_per_second × idleTimeout_seconds × 5`; at 1000 conn/s with the default 60s timeout that is about 300k. When `maxSessions` is reached the least recently seen entry is evicted, which breaks live connections if you are under-provisioned.
- **Size descriptors and source ports.** There is one connected, explicitly bound UDP socket per client tuple. Flow capacity is `maxSessions / 4` (minimum 256). The process raises `RLIMIT_NOFILE` and reports the Linux ephemeral-port range; a common range has only 28,232 ports shared with other processes in that network namespace. Descriptor or port exhaustion recycles a flow and retries once. Raising `ulimit` alone cannot provide more ports. Partition network namespaces/source capacity for larger deployments.
- **One dataplane core per process.** `SO_REUSEPORT` hashes tuples between processes sharing a network namespace. State is not shared: NAT rebinding or changing the worker set can select a worker without the connection's aliases. Kubernetes replicas instead have independent namespaces and rely on Service/LB flow affinity. Keep worker ownership stable or use coordinated CID-aware steering; scaling is not automatically migration-safe.
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

Dependencies are OpenSSL 3.0+ libcrypto, libyaml, POSIX threads, CMake 3.25+, and a C23 compiler (Clang 18+ or GCC 14+). The end-to-end targets need Docker and outbound network access to build the aioquic test image. [.devcontainer/](.devcontainer/) has a container with everything preinstalled.

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
  fwmark: 0                # optional Linux SO_MARK; 0 disables, restart required
  transparent: false       # optional Linux client source tuple toward backends; restart required
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

- The only top-level keys are `listen`, `sessions`, `routes`, `cidEncoding`, `quicLb`, and `logging`. Anything else is an error rather than a silently ignored typo.
- Each route requires `host` and `port`, with optional `serverId` for qsr-authenticated CIDs or `quicLbServerIds` for QUIC-LB. Other keys are rejected.
- SNI keys are lower-cased and validated as DNS names: no empty labels, no leading hyphens, 255 characters max.
- An empty file means defaults.

With `logging.connections: true` you get one line when a flow opens and one when it closes:

```text
conn: open src=203.0.113.7:51820 sni=rvr-a.example scid=8f2c01ab backend=10.0.4.12:8443 via=10.0.4.1:36015
conn: close src=203.0.113.7:51820 sni=rvr-a.example scid=8f2c01ab backend=10.0.4.12:8443 via=10.0.4.1:36015 reason=idle duration=63s
```

`via` is the router's source address and port toward the backend for that flow, i.e. the peer the backend logs. It joins a backend access log line (`10.0.4.1:36015`) back to the client in `src`. Ephemeral ports are reused, so match within the window between a flow's `open` and `close`. A client that migrates or NAT-rebinds gets a new flow, so it logs a new `open` with a new `via`; the backend sees the same change as a path migration.

Close reasons are `idle`, `evicted`, `reload`, `shutdown`, and `error` (including backend rerouting). Lifecycle records pass through a bounded nonblocking pipe to a logging thread; a slow collector drops records rather than blocking forwarding. `log_drops` reports queue losses. Shutdown may discard queued records. Logging is hot-reloadable.

### Policy routing with a socket mark (Linux)

Set `listen.fwmark` to a decimal integer in `0..4294967295`. Omitted or `0`
leaves socket marking disabled. A nonzero value applies Linux `SO_MARK` to the
main UDP listener and every per-flow upstream UDP socket, before bind/connect,
for both IPv4 and IPv6. It labels QSR's outgoing packets with local kernel
metadata; the mark is not sent over the network or inherited by backend applications.

For example, with `listen.fwmark: 12345`, an administrator can install:

```sh
ip -4 rule add pref 90 fwmark 12345 lookup main
ip -6 rule add pref 90 fwmark 12345 lookup main
```

Choose a priority ahead of the conflicting policy rule and ensure `main` has
the desired routes. QSR does not install rules or assume a WireGuard/WARP mark
or table. A mark alone does not select a route. Reply source-address/interface
preservation remains active; the selected route must be compatible with it.

Setting a nonzero mark requires `CAP_NET_ADMIN`, or `CAP_NET_RAW` on Linux 5.17
and later, in the user namespace governing the network namespace. The capability
must remain available for new upstream sockets throughout the process lifetime.
Listener marking failure aborts startup; upstream marking failure rejects that
flow instead of sending unmarked traffic. Both report `SO_MARK`, the socket role,
mark, and OS error regardless of connection logging. Nonzero marks are rejected
on non-Linux platforms. Changes require a process restart and are ignored with
a warning on hot reload, including for subsequently created upstream sockets.

For Kubernetes configuration and capability settings, see the
[Helm chart policy-routing example](charts/quic-sni-router/README.md#policy-routing-linux).

### Transparent client source (Linux)

By default a backend sees the router as the peer of every flow, and
`via=` in the connection log is the only way back to the client. With
`listen.transparent: true`, each per-flow upstream socket is bound to the
client's own address and port (`IP_TRANSPARENT`/`IPV6_TRANSPARENT`) before it
connects, so the backend sees the real client tuple in its own logs, rate limits
and access lists, and `via=` equals `src`. Source addresses can be spoofed, so
read [Spoofed client addresses](#spoofed-client-addresses) before relying on them
for access control.

```yaml
listen:
  udp: ":443"
  transparent: true
```

Two things must be in place, and QSR provides neither:

1. **Privilege.** Setting the option needs `CAP_NET_RAW` or `CAP_NET_ADMIN` in
   the user namespace governing the network namespace, for the whole process
   lifetime. Unlike `SO_MARK`, `CAP_NET_RAW` is enough on every supported
   kernel (since Linux 3.2). Startup probes it and refuses to run without it.
2. **A return path.** Backend replies are addressed to the client. They must be
   delivered locally to the router's flow socket instead of being routed toward
   the client. Route them to `lo` by source, one rule per backend (`ipproto`
   and `sport` matches need Linux 4.17 or later):

   ```sh
   ip -4 route add local 0.0.0.0/0 dev lo table 100
   ip -4 rule add pref 90 from 10.0.4.12 ipproto udp sport 8443 lookup 100
   ```

   This also covers backends on the router host itself, including `127.0.0.1`.
   For packets arriving on an interface, matching the socket instead of the
   source works too (the nftables `socket` expression needs Linux 4.18 or later):

   ```sh
   nft add table inet qsr
   nft add chain inet qsr prerouting '{ type filter hook prerouting priority mangle; }'
   nft add rule inet qsr prerouting ip saddr 10.0.4.12 udp sport 8443 socket transparent 1 meta mark set 0x100
   ip -4 rule add pref 90 fwmark 0x100 lookup 100
   ```

   For IPv6 backends use `ip -6`, `local ::/0`, and `ip6 saddr`. A backend on
   another host must route client addresses back through the router host
   (default route or a policy rule on the backend); otherwise its replies bypass
   the router and the client drops them. Table `100` and mark `0x100` are
   examples: choose values that collide with neither existing policy rules,
   `listen.fwmark`, nor marks your CNI uses.

`make test-e2e-transparent` installs these recipes exactly as shown (IPv4,
IPv6, and a same-host `127.0.0.1` backend for the source rule; IPv4 for the
nftables rule) in throwaway network namespaces, and checks the backend's view
and the reply path, plus the same setups without a return path.

A transparent tuple keeps its family: IPv4 clients (including v4-mapped clients
on a dual-stack listener) reach IPv4 backends, IPv6 clients IPv6 backends.
While the mode is active, startup and reload log the excluded family per route. Failures are fail-closed:
a flow whose bind fails is dropped and never retried from the router address.
`SIGUSR1` and shutdown metrics count `transparent_open_failures`,
`transparent_bind_conflicts` (another socket owns the client tuple) and
`transparent_family_mismatches`; stderr gets one line per class per minute.
Rejected on non-Linux platforms. Changes require a process restart and are
ignored with a warning on hot reload.

For Kubernetes, see the
[Helm chart transparent-source notes](charts/quic-sni-router/README.md#transparent-client-source-linux).
Enabling it through the chart also sets the Service's `externalTrafficPolicy`
to `Local`, overriding `service.externalTrafficPolicy`. The chart README says
what to do for each load balancer (MetalLB, Cilium BGP and L2 announcements,
cloud) and each backend placement, including Cilium's per-pod source check.

#### Spoofed client addresses

Without this option backends only ever see the router's address. With it they
see whatever source address reached the router, and UDP source addresses can
be forged:

- A backend access list that trusts internal ranges accepts an internet packet
  claiming an internal source, unless the router's ingress drops it. Without
  the real owner of that address the QUIC handshake cannot complete, but the
  backend still processes the forged Initial packets.
- The backend replies to the claimed address. When that address is on the
  backend's own network, the reply goes there directly instead of through the
  router, so a forged Initial makes the backend send handshake packets (up to
  QUIC's threefold anti-amplification limit) at an internal host. Backends that
  send QUIC Retry validate the address first.

Before enabling transparent mode, drop internal, loopback and other bogon
sources on the router's public interface: BCP 38 upstream, strict `rp_filter`,
or an nftables `fib saddr . iif oif missing drop` rule. See the
[threat model](docs/threat-model.md).

### Hot reload

The directory holding `config.yaml` is watched with `inotify`. Completed writes, atomic file replacement, and Kubernetes `..data` swaps trigger a background parse and DNS resolution. Intermediate modifications and unrelated filenames are ignored. One worker builds a candidate at a time; updates arriving during resolution schedule another candidate before publication. The dataplane atomically publishes valid candidates and evicts sessions whose backend disappeared. This deliberately terminates those sessions, and is not a lossless reload guarantee. Changes to `listen.udp`, `listen.fwmark`, `listen.transparent`, and `sessions.maxSessions` require restart.

DNS timeouts no longer stall packet forwarding; failed candidates retain the previous configuration. Startup still resolves synchronously, and process shutdown waits for an outstanding resolver worker. Prefer atomic rename for config updates: completed-write notifications cannot make arbitrary concurrent in-place writers transactional.

### Linux I/O and operational signals

Wildcard listeners prefer dual-stack IPv6 with IPv4 fallback. Explicit IPv6 addresses use `[::1]:8443`. Replies preserve the local destination address/interface via packet-info ancillary data. Routing state remains per client tuple; concurrent connections from one client tuple to different local VIPs/backends need separate router instances/listeners.

The receive path reserves 64 KiB per GRO slot and rejects payload/ancillary truncation. Compatible same-destination batches use UDP GSO with per-datagram fallback. Individual datagrams remain capped at 1500 bytes; jumbo QUIC datagrams are not supported. Startup logs effective kernel socket buffers and port capacity.

- `SIGUSR1`: emit live counters, including kernel drops, send errno counts, truncations, allocation failures, evictions, GSO batches, and log drops.
- `SIGUSR2`: stop admitting unknown connections, continue routing existing state/authenticated CIDs, and exit once flows expire. Keep the LB delivering established traffic while draining; encrypted QUIC close frames cannot be observed, so idle expiry determines completion.
- `SIGTERM` / `SIGINT`: flush queued sends and close immediately. They do not preserve active connections. A Kubernetes grace period or `maxUnavailable: 0` alone does not make rollouts connection-preserving.

Authenticated CID routing has a new, incompatible format; see [docs/cid-routing.md](docs/cid-routing.md) before upgrading backends using `cidEncoding`.

For cooperating backends that issue QUIC-LB CIDs, the alternative `quicLb` mode
supports the encrypted and unencrypted formats of draft-ietf-quic-load-balancers-21,
multi-byte server IDs, and overlapping configurations for key rotation. See
[docs/quic-lb.md](docs/quic-lb.md) for configuration and compatibility boundaries.
QUIC-LB encryption is not CID authentication; this mode is mutually exclusive
with `cidEncoding`.

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
          mountPath: /config
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
| `make test-e2e-transparent` | transparent mode in throwaway network namespaces, using the README return-path recipes: real client tuple at the backend and reply delivery for IPv4, IPv6 and same-host backends, and no reply without a return path (needs unprivileged user namespaces, `iproute2` and `nsenter`, and skips otherwise; the nftables case also needs `nft` and the kernel's `nft_socket` module, and skips alone without them) |
| `make test-loadtest` | 10 backends under sustained concurrent handshakes, asserting zero misroutes |

`make test-loadtest` takes `QSR_LOADTEST_DIRECT=1` to bypass the router for a baseline, and `QSR_LOADTEST_PERSISTENT=1` to reuse one HTTP/3 session per worker.

## Prior work

`dlundquist/sniproxy` for the separation of listener, parser, route table, and forwarder. `AGWA/snid` for a minimal SNI demux philosophy and its backend safety constraints. `HyBuildNet/quic-relay` for a Go take with handler chains, load balancing, and optional TLS termination. [docs/inspirations.md](docs/inspirations.md) covers what does and does not carry over from TCP SNI proxies.

## License

Copyright 2026 Peinser BV. Apache 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
