# Changelog

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project intends to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from 1.0 onward. Pre-1.0 releases may break wire-adjacent behaviour without a major bump.

## [Unreleased]

### Fixed

- **Backend QUIC Retry routing**: Retry packets are long-header packets but not Initials, so the router previously did not learn the backend's Retry SCID. Post-Retry client Initials now route via that learned DCID alias instead of needing to decrypt and re-parse the second ClientHello flight. Long-header backend responses can also use a learned DCID-to-client alias even when the observed backend source tuple does not exactly match the configured backend address, which is useful behind Kubernetes/NAT paths.
- **Dynamic backend source classification**: backend packets may arrive from a selected pod tuple rather than the configured Service tuple. The router now treats observed backend-source tuples as known backends for stale-Initial, CID, and post-idle reset routing decisions, preventing those pod tuples from being mistaken for clients after backend idle expiry.
- **Post-idle stateless reset routing**: established client-to-backend packets now refresh the backend-to-client reverse tuple before forwarding, and backend-to-client packets pin the client tuple back to the observed backend source. This keeps backend stateless resets generated after a backend idle timeout on the client tuple that triggered them, instead of following stale reverse state from an earlier packet or a Kubernetes Service/pod tuple mismatch.
- **Partial ClientHello SNI extraction**: resumed Chromium/Brave QUIC handshakes can produce a larger ClientHello where SNI is present in the first Initial but later PSK/resumption extensions are not. The SNI parser now returns as soon as the complete server_name extension is available instead of requiring the entire declared ClientHello body.
- **Fragmented Initial routing**: fresh client Initials whose CRYPTO data arrives across multiple datagrams can now be buffered briefly and routed once enough contiguous ClientHello bytes are available to read SNI. The pending buffer is bounded by source/CID, packet count, datagram size, and idle timeout, and is heap allocated so constrained Kubernetes stacks do not crash before startup logs are emitted.
- **Source-port-reuse misrouting**: when the kernel quickly reassigned an ephemeral UDP source port to a fresh `connect()`, the new QUIC Initial arrived on a tuple that matched a stale forward-alias from the previous connection in our session table, and was misrouted to the previous backend. The wrong backend's AEAD then rejected the packet, the client retransmitted, was still misrouted, and the connection eventually timed out. `handle_packet` now routes long-header Initial packets by their (DCID, SCID) pair-key first; tuple match is only honoured for non-Initial packets, or for Initials whose tuple-matched destination is NOT a configured backend (i.e., a reverse alias for a server's Initial response). Bug discovered by the new loadtest e2e, which is the regression net going forward (zero-tolerance misroute assertion).
- **Backend reverse-tuple ambiguity**: backend return traffic was previously allowed to route through a single reverse tuple alias (`backend_ip:port -> client`). That is ambiguous because one backend UDP socket serves many concurrent QUIC connections; the alias could be overwritten by another connection, sending backend packets to the wrong client and producing AEAD rejection/timeouts. Packets from configured backends now prefer learned long-header/short-header DCID aliases before backend tuple fallback.
- **Backward-shift deletion in `table_delete_at`** had a stop-condition that fired only when `distance == 0`; the move is also invalid in the wrap-around case where the entry's natural slot is between cursor and next. Latent under FNV-1a's distribution; SipHash's better one made it observable. Replaced with the correct two-distance comparison.

### Added (testing)

- **Loadtest e2e** at `tests/e2e/loadtest/`: 10 aioquic HTTP/3 backends behind the router, a Python concurrent client (`loadtest_client.py`) that opens fresh QUIC handshakes through the router at the configured concurrency for the configured duration, verifies each response body matches the routed-to backend (catches misrouting at runtime), and reports throughput + p50/p95/p99 latency. Pass criteria: zero misrouted responses AND success rate ≥ threshold (default 95%). New `make test-loadtest` target, new `loadtest` CI job. Surfaces routing bugs that the small-scale http3 e2e (2 backends, 4 connections) can't trigger — found the source-port-reuse misrouting bug on first run.
- **Persistent loadtest mode**: `QSR_LOADTEST_PERSISTENT=1 make test-loadtest` keeps one QUIC/HTTP/3 session open per worker and sends repeated requests on new streams. `QSR_LOADTEST_DIRECT=1` bypasses the router for baseline comparison.

### Security

- Replaced FNV-1a with SipHash-2-4 in the session and route tables. A 16-byte hash key is seeded from `getrandom(2)` at process startup; an attacker controlling QUIC DCIDs or SNIs can no longer force open-addressed-table probe walks via collision crafting. RFC test vectors pinned in `tests/unit/test_hash.c`.
- Refused short single-CID aliases. `qsr_session_single_cid_key` returns an invalid key for CID lengths below `QSR_MIN_LEARNED_CID_LEN` (8, matching RFC 9000 §17.2 SHOULD); `lookup_short_header_cid` iterates from that floor. Closes a short-header false-match amplification vector where an attacker who established a connection with a 1- or 2-byte SCID could cause subsequent unrelated short-header packets to false-route at rate ≈ N_sessions / 256^len per try. Per-try probability at the new floor is ~5e-15 even at 100K sessions.
- `qsr_hash_bytes` now aborts on `getrandom` failure instead of returning a constant sentinel. The previous behaviour silently re-enabled the hash-flooding vector for the lifetime of the process; fail-hard is the correct response for a single irrecoverable condition.
- Tightened the ACK-frame `range_count` bound in `qsr_quic_extract_crypto` from `range_count > plaintext_len` to `range_count > (plaintext_len - offset) / 2`. Each range is ≥2 varint bytes, so the new bound matches the minimum encoding size and short-circuits CPU-burning loops before the varint parse.
- `qsr_config_load` rejects YAML scalars containing embedded NUL bytes. Operator config is trusted but the check is one `memchr` and removes a category of "prefix-matches-but-actually-evil" footguns from any future `strcmp` against parsed key/value strings.

### Changed

- Restructured `src/tls_client_hello.c` around a small `reader_t` abstraction with fail-fast typed reads (`r_u8` / `r_u16` / `r_u24` / `r_skip`) and length-prefixed sub-readers that physically cannot walk past their declared parent length. Replaces 14 hand-rolled `if (offset > end || N > end - offset)` checks with one bounds check per field. Same wire-level semantics; `QSR_ERR_TRUNCATED` vs `QSR_ERR_INVALID` is now reported more accurately (a too-short handshake header was previously conflated as INVALID — it's TRUNCATED).

### Performance

- `qsr_route_table_has_backend` now uses a resolved backend-address hash index instead of scanning all routes. This removes an O(routes) check from backend-source detection on the dataplane path and from hot-reload session classification.
- `learn_long_header_cids` and `lookup_rebound_initial` peek the long-header bit before invoking the QUIC Initial parser. These are called on every packet of every established session, and the overwhelming majority are short-header 1-RTT packets that the parser would fast-fail anyway — peek shaves ~10ns/packet off the steady-state hot path.
- Combined `qsr_session_table_put`'s lookup + insertion-slot probe into a single open-addressing walk. The previous shape hashed and probed twice per insert; new shape walks the table once and only re-walks after eviction (bounded at exactly 2 walks per put).
- Removed a 1500-byte stack-array zero-init from `qsr_quic_decrypt_initial`; the buffer is immediately fully overwritten by a `memcpy` of the packet, so the zero-init was pure waste on every new-session decrypt.

### Added

- QUIC v2 (RFC 9369) Initial packet support — version-aware salt, HKDF labels (`quicv2 key`/`iv`/`hp`), and Initial-type-bit table. Unit tests pin v1 derivation against RFC 9001 Appendix A.1 and v2 against RFC 9369 Appendix A. End-to-end Docker test exercises both versions × both backends per run.
- Hot reload of the route configuration via `inotify` on the config directory. ConfigMap updates (or any file edit that replaces the inode) trigger re-parse, DNS re-resolve, and an atomic route-table swap. Sessions whose backend disappeared from the new config are evicted (hard cutover); sessions whose backend was preserved keep going. Parse or resolve failures keep the previous config serving traffic.
- Per-route logging: each route is logged on startup, and reloads emit `+ route`, `~ route`, `- route` diff lines plus a summary.
- libyaml-backed config parser, replacing the hand-rolled state machine. Anchors, aliases, multi-line scalars, and comments anywhere are now accepted; unknown top-level or per-route keys are still rejected as typos.
- Helm chart at [charts/quic-sni-router/](charts/quic-sni-router/) with hardened security defaults (`runAsNonRoot`, `cap drop ALL`, `automountServiceAccountToken: false`, `readOnlyRootFilesystem: true`), `PodDisruptionBudget`, `topologySpreadConstraints`, and `values.schema.json`. Published to `oci://harbor.peinser.com/library/charts/quic-sni-router` on every push to main.
- Multi-arch image (`linux/amd64` + `linux/arm64`) published per push.
- Anti-amplification: client Initial datagrams shorter than 1200 bytes from unknown sources are dropped without any HKDF/AES work (RFC 9000 §14.1).
- Strict QUIC Initial validation: long-header bit, fixed bit, version-specific type bits, DCID length ≥ 8, payload length ≥ 36.
- `SIGINT`/`SIGTERM` graceful shutdown; `SIGPIPE` ignored.
- `SO_REUSEPORT` set so multiple router processes can share UDP/443; `IPV6_V6ONLY=0` for dual-stack listeners.
- Monotonic clock for session idle expiry (immune to wall-clock jumps).
- LRU eviction when the session table is at capacity, with backward-shift deletion preserving probe-chain integrity.
- Per-source rate limiting? No — see [ROADMAP.md](ROADMAP.md).

### Changed

- Removed the synchronous `io_uring` dataplane path: it did `submit; wait_cqe` per packet and was strictly slower than batched `recvmmsg`/`sendmmsg`. A proper async rewrite is in [ROADMAP.md](ROADMAP.md).
- Modernised to C23 (`-std=gnu23`, `nullptr`, `[[nodiscard]]`, designated initialisers).
- Refactored hot-reload state out of `src/udp.c` into a dedicated `qsr::runtime` module.

### Security

- See [docs/threat-model.md](docs/threat-model.md). Recent additions: the 1200-byte minimum on unknown-source Initials; stricter parser validation; the fail-closed reload that keeps the old config running on a bad update.
