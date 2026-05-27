# Examples

## Development Container

The devcontainer follows the Tower operator pattern and uses `.dev/compose.yml`.

Services:

- `devcontainer`: C/CMake development environment.
- `flightdeck-rvr-a`: UDP echo backend on `8443/udp`.
- `flightdeck-rvr-b`: UDP echo backend on `8444/udp`.

The container mounts host git, SSH, Claude Code, and opencode state into `/root` for direct access inside the container.

## Static Routes

```yaml
listen:
  udp: ":443"
sessions:
  idleTimeout: 60s
  maxSessions: 100000
routes:
  rvr-a.flightdeck.tower.peinser.com:
    host: flightdeck-rvr-a
    port: 8443
  rvr-b.flightdeck.tower.peinser.com:
    host: flightdeck-rvr-b
    port: 8444
```

Unknown SNI and malformed traffic are dropped by design. There is no fallback route in the MVP.

## Local Commands

```sh
make build
make test
make sanitize
make fuzz-smoke
```

`make fuzz-smoke` requires a clang toolchain with libFuzzer. On macOS AppleClang may not include it, so run fuzzing in the devcontainer or CI.

## Route Lookup Design

Routes are normalized to lowercase ASCII DNS names at load time and indexed in an open-addressed hash table. Backend hostnames are resolved before the UDP loop starts, so packet processing does not block on DNS. Future hot reload should build a complete immutable route snapshot, validate and resolve it, then atomically swap the dataplane pointer.

## Session Lookup Design

Sessions use bounded open addressing and reject invalid key lengths before hashing or comparing memory. The dataplane creates multiple aliases for a routed flow:

- client tuple to backend tuple
- observed Initial CIDs to backend tuple
- backend tuple to client tuple

The tuple alias is the fast path. If a client sends a later packet from a different NAT tuple with a learned CID, the router adds a new tuple alias and updates the backend reverse alias to the new client tuple.

Short-header rebinding is best-effort because QUIC does not encode Destination Connection ID length in the short header. The router tries learned CID aliases from longest to shortest and then pins the new tuple if there is a match.

## Linux Dataplane

Linux builds use a nonblocking UDP socket with `epoll`, `recvmmsg` receive batching, and `sendmmsg` send batching (up to 32 datagrams per syscall). macOS and other development platforms use the portable blocking `recvfrom`/`sendto` path.

The earlier `io_uring` path was synchronous (submit-then-wait per packet) and slower than `recvmmsg`/`sendmmsg`; it has been removed. A proper async rewrite using multishot recv and registered buffers is the right way to revisit and is tracked as future work.

## Scaling and Operations

- The dataplane is single-threaded. To use more cores, run multiple router processes bound to the same address; the kernel hashes flows across them via `SO_REUSEPORT` (set automatically on Linux). On Kubernetes this is typically a Deployment with `replicas > 1` plus a Service routing to the host port.
- Idle expiry uses `CLOCK_MONOTONIC`, so an NTP step or wall-clock adjustment will not flush sessions.
- `SIGINT` and `SIGTERM` trigger a graceful shutdown: the loop drains, sender flushes, sockets close. Kubernetes' default `SIGTERM` plus `terminationGracePeriodSeconds` is sufficient.
- Backends are resolved at startup AND on every hot reload (see below). If only the *IP* behind a stable hostname changes (no config edit), restart the router (`kubectl rollout restart deploy/quic-sni-router`).

## Hot reloading the route config

The directory containing the config file is watched with `inotify`. Any of the following triggers re-parse + DNS re-resolve + atomic route-table swap:

- An editor's atomic-rewrite (write tmp + rename).
- `kubectl cp` / `docker cp` of a new file.
- A Kubernetes `ConfigMap` update — kubelet swaps the `..data` symlink in the mount directory, which fires `IN_MOVED_TO` on the dir.

What happens on reload:

| Field in new config | Behaviour |
| --- | --- |
| `routes` (added / removed / changed) | Routes swap atomically. Sessions to a backend that's no longer in the new config are evicted (hard cutover); sessions to surviving backends keep going. New clients see the new routes. |
| `sessions.idleTimeout` | Updated; takes effect on the next expiry sweep (within 1s). |
| `listen.udp` | Logged + ignored. Requires process restart. |
| `sessions.maxSessions` | Logged + ignored. Requires process restart. |

Validation is fail-closed: if the new file fails to parse, or any backend hostname fails to resolve, the previous config keeps serving traffic and the reason is logged to stderr.

Operator workflow when using a Kubernetes operator that owns the ConfigMap:

1. The operator updates the `ConfigMap` (`kubectl apply -f ...` or via its informer).
2. kubelet syncs the file into each router pod's mount (typically within 60s; controllable via `terminationGracePeriodSeconds` and the kubelet's `--sync-frequency`).
3. `inotify` in each router fires; the router re-parses, re-resolves, evicts dropped-backend sessions, swaps. No pod restart, no in-flight datagram loss for sessions whose backend survived.

To force-pick-up an IP change without a config edit (e.g., a backend pod was rescheduled and got a new ClusterIP), trigger a deliberate change — bump a comment in the ConfigMap so the file content differs and kubelet re-syncs.

## Kubernetes Backend Services

Routing to a Kubernetes `Service` is possible, but the Service must not spray packets from a single QUIC connection across multiple pods. QUIC connection state lives in one backend process; if later datagrams land on a different pod, that pod will not know the connection ID and the connection will fail.

One acceptable Service configuration is UDP `ClientIP` affinity:

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

The matching router config can point at the Service DNS name:

```yaml
listen:
  udp: ":443"
routes:
  rvr-a.flightdeck.tower.peinser.com:
    host: flightdeck-rvr-a.tower-system.svc.cluster.local
    port: 8443
```

This preserves connection correctness only as long as Kubernetes keeps packets from the router pod's source IP pinned to the same backend endpoint. It is not QUIC-aware load balancing. If many client sessions arrive through one router pod, `ClientIP` affinity can pin them all to one backend pod. For predictable balancing, prefer direct pod endpoints through a headless Service, one Service per backend instance, or a downstream load balancer that understands QUIC connection IDs.
