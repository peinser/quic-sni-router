# Roadmap

What's planned, why it's worth doing, and what would block someone from picking it up. PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). This list is intentionally opinionated; "no" entries are as important as "yes" entries.

## Near term (0.x)

- **Metrics endpoint (Prometheus exposition format)**. The `qsr_metrics_t` struct in [include/qsr/metrics.h](include/qsr/metrics.h) exists but is never populated. Wire counters in the dataplane (datagrams in/out, parse_failures, unknown_sni, sessions_active) and expose them on a small admin HTTP port. Unlocks `ServiceMonitor` and HPA in the Helm chart.
- **Periodic backend DNS re-resolve**. Today resolution happens at startup and on config reload; an IP change behind a stable hostname requires a kick. A 60s re-resolver that swaps the route's `backend_addr` atomically would close this gap. Watch out for race with the hot-reload path — the new periodic re-resolver should call into the runtime module, not edit the route table directly.
- **Per-source rate limit**. CPU-DoS shield independent of upstream BCP 38. Token bucket per `/24` (or `/64` for v6), bounded LRU map. Drop Initials over budget before HKDF/AES. Default: very generous (e.g., 1000 Initials/s per /24).
- **Wildcard / suffix SNI routes**. `*.example.com` → backend. Compile-time: change route lookup from exact `strcmp` to a two-pass (exact, then longest suffix). Bounded cost since route count is ≤ 1024.
- **Fallback / catch-all route**. Today, no-route SNIs are dropped. An optional `default:` route would let operators front a generic backend or a "you've reached an unknown service" responder.
- **Connection draining on SIGTERM**. Right now SIGTERM stops accepting new packets and exits within `terminationGracePeriodSeconds`. A draining mode (stop NEW sessions, keep forwarding for existing ones until idle) makes rolling updates lossless for in-flight QUIC connections. Needs a session-classifier (existing vs. new) on the recv path.

## Mid term

- **io_uring fast path, done properly**. The earlier synchronous io_uring path was strictly slower than `recvmmsg`/`sendmmsg` and got removed. A real rewrite uses multishot recv (`IORING_RECV_MULTISHOT`), registered buffers, and zero-copy send. Worth doing once we have benchmarks that show user-space lookup is no longer the bottleneck.
- **GSO/GRO (segmentation offload)**. Linux UDP supports send-side `UDP_SEGMENT` and recv-side `UDP_GRO`. For high-rate flows this is a 2-3x throughput win. Requires kernel ≥5.0 and `setsockopt(UDP_GRO, 1)`.
- **HostName / SAN map per route**. SNIs are matched as-is today. For deployments with many SAN-aliased hostnames behind one backend, a `aliases: [a, b, c]` field would avoid repetition.
- **Native multi-arch image builds (no QEMU)**. The image workflow currently cross-builds arm64 under QEMU. With on-prem arm64 runners + the matrix-and-merge pattern (which we had in an intermediate revision), the arm64 build runs natively at ~3× the speed.
- **Helm `ServiceMonitor` + HPA templates**. Depends on the metrics endpoint above. Add an opt-in `serviceMonitor.enabled` and an HPA targeting `datagrams_in` rate.
- **Helm chart-test container**. Add `templates/tests/test-connection.yaml` so `helm test` does a basic post-install QUIC handshake against the rendered Service.

## Longer term / speculative

- **QUIC Retry token issuance**. Would let the router validate the client source address before forwarding to the backend, closing the spoofed-source amplification window. Costly: requires a per-router signing key (breaks the "router holds no keys" invariant) and a Retry/Initial state machine. Probably better deferred to a proper QUIC stack.
- **NEW_CONNECTION_ID learning**. To track CID rotations after the handshake, we'd need to decrypt at least one Handshake packet to bootstrap 1-RTT keys. This makes the router a partial QUIC stack — a big design shift. Today, long-lived sessions through aggressive NAT may break; document the limit instead.
- **ECH (Encrypted ClientHello) policy**. ECH fundamentally hides the SNI. The router cannot route ECH traffic and never will, by design. We could detect ECH and emit a distinct counter / log so ops can see the volume — useful as an observability hook even if routing isn't possible.
- **Admin socket (UNIX socket, signal alternative)**. A small UNIX-domain control socket for `dump routes`, `dump sessions`, `drain` commands. Cleaner than relying on SIGHUP or log scraping. Carefully scoped — no `set route` (that path goes through the file).

## Explicit non-goals

- Becoming a full QUIC stack. We deprotect only Initial packets, enough to read the SNI. Anything beyond that — handshake termination, 1-RTT decryption, key updates, NEW_CONNECTION_ID issuance — is out of scope.
- Holding private keys. The router never loads cert or key material. Backends terminate TLS/mTLS.
- TCP fallback. Pass-through TCP/443 (HTTPS) is a different problem with a long lineage of solutions ([sniproxy](https://github.com/dlundquist/sniproxy), [snid](https://github.com/AGWA/snid)). This project stays QUIC-only.
- Per-connection authorization or content inspection. The router does SNI lookup and forwards bytes. Anything more belongs in the backend or a QUIC-aware sidecar.

## How to propose a feature

Open an issue with: the use case, what you've already tried, and (if possible) a sketch of the wire-level behaviour. For substantial features, draft an entry in this file under "Near term" or "Mid term" as part of the PR.
