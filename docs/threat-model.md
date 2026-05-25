# Threat Model

The router sits at the WAN edge for UDP/443 and routes by Initial-packet SNI without terminating TLS. Trust boundaries:

```text
WAN  --(UDP/443)-->  quic-sni-router  --(UDP/private)-->  backend pods
```

## Assets

- Availability of UDP 443 routing.
- Confidentiality of pod-terminated mTLS sessions (the router never sees plaintext after the ClientHello).
- Integrity of route configuration.

## Non-goals

- TLS termination.
- Private-key handling.
- Decrypting application data.
- Full QUIC stack: no version negotiation, no retry-token issuance, no path validation, no NEW_CONNECTION_ID handling.

## Primary risks

| Risk | Vector | Mitigation in this codebase |
| --- | --- | --- |
| Parser memory-safety bugs | Malformed QUIC/TLS inputs | Bounded reads, fuzz harnesses (`fuzz_quic_initial`, `fuzz_quic_frames`, `fuzz_tls_client_hello`), ASAN/UBSAN in CI, hardened parsers |
| CPU exhaustion via parse floods | High-rate forged Initial datagrams | Reject datagrams shorter than 1200 bytes from unknown sources before any HKDF/AES work (RFC 9000 §14.1 floor); reject malformed long headers before crypto |
| Reflection / amplification | Spoofed source on Initial | 1200-byte minimum gives the attacker no amplification (request size >= response size); deploy with upstream BCP 38 filtering for full protection |
| Session-table flooding | Spam Initials to exhaust the table | LRU eviction on insert when at capacity (`max_sessions`); legitimate active sessions survive against low-rate attackers, but a sustained flood will still churn the table — combine with upstream rate limits |
| Stale sessions | Backend IP change without restart | Backends are resolved at startup AND on every hot reload of `config.yaml` (inotify-driven). For an IP change behind a stable hostname with no config edit, bump the ConfigMap so the file content differs, or `kubectl rollout restart` |
| Session-table hash flooding | Attacker-controlled CIDs collide on the open-addressed table, forcing O(N) probe walks per lookup | Session and route tables use SipHash-2-4 with a 16-byte per-process key seeded from `getrandom`. Collision-forcing is cryptographically infeasible. `qsr_hash_bytes` aborts on `getrandom` failure (would otherwise silently re-enable hash flooding) |
| Short-header CID false-match | Attacker plants a 1- or 2-byte CID via Initial; subsequent short-header packets from anywhere false-match it at rate ≈ N_sessions / 256^len | Single-CID aliases shorter than `QSR_MIN_LEARNED_CID_LEN` (8, matching RFC 9000 §17.2 SHOULD) are refused at table-insertion time; lookup iteration is bounded to the same floor. At len=8 with 100K sessions the per-try probability is ~5e-15 |
| Reload-time disruption | Operator pushes a broken config | Reload is fail-closed: parse + DNS-resolve must both succeed before the new routes are swapped in. On any failure the previous config keeps serving and the failure is logged |
| Backend-spoofing return traffic | Attacker on WAN sends packets with source = backend IP | The router forwards any packet whose source tuple matches a learned backend tuple back to the associated client. Mitigated by binding backends to non-routable / cluster-internal addresses and by QUIC's own AEAD on the client side |
| Route confusion | Ambiguous / malformed SNI | SNI is normalized to lowercase ASCII DNS, label-validated (no leading hyphen, no empty labels), max 255 chars; unknown SNI is dropped |
| Session hijack via guessed CID | Attacker injects short-header packet with known CID | CID lookup only happens when the source tuple does not match a session; QUIC AEAD on the client rejects the resulting garbage. Out-of-scope: forgery resistance requires QUIC retry tokens, which this router does not issue |

## Controls in code

- Hard datagram cap (`QSR_MAX_DATAGRAM_SIZE` = 1500) and ClientHello reassembly cap (`QSR_MAX_CLIENT_HELLO_SIZE` = 8192).
- Hard session cap (`maxSessions`, default 100000) with LRU eviction on overflow.
- Idle expiry on `CLOCK_MONOTONIC` (immune to wall-clock jumps), default 60 s.
- Strict QUIC Initial validation: long-header bit, fixed bit, type bits matching the announced version's Initial encoding (v1 = `0b00`, v2 = `0b01`), version in `{v1, v2}`, DCID length >= 8, payload length >= 36.
- Reject client Initial datagrams below 1200 bytes from unknown sources.
- libFuzzer harnesses for `qsr_quic_parse_initial`, `qsr_quic_extract_crypto`, and `qsr_tls_client_hello_sni`. The Initial fuzzer drives the full deprotect -> CRYPTO -> ClientHello pipeline and covers both v1 and v2.
- Unit tests pin v1 key derivation against RFC 9001 Appendix A.1 and v2 against RFC 9369 Appendix A (see [tests/unit/test_quic_crypto.c](../tests/unit/test_quic_crypto.c)). A v1-vs-v2 differ test catches accidental cross-contamination of salts or labels.
- Config parser delegated to libyaml (well-fuzzed upstream via oss-fuzz); our wrapper validates the schema strictly (unknown keys are errors, not silent defaults).
- Hot reload (`src/runtime.c`) is fail-closed: a parse or DNS-resolve failure on the new file keeps the previous config serving traffic and logs the reason. Session disruption on reload is bounded — only sessions whose backend disappeared from the new config are evicted (`qsr_session_table_evict_if` + `qsr_route_table_has_backend`).
- ASAN/UBSAN CI run on every commit.
- Graceful shutdown on SIGINT/SIGTERM; SIGPIPE is ignored.
- `SO_REUSEPORT` set so the operator can scale by launching multiple dataplane processes.

## Operational controls that are NOT in this binary

These belong in the deployment, not the router process:

- BCP 38 / uRPF on the upstream router to drop spoofed source IPs.
- Per-source rate limiting (eBPF / nftables / cloud LB).
- Backend network isolation: backends should not be reachable from the WAN; the router should reach them via a private interface or cluster network.
- Bind the listener with a Kubernetes NetworkPolicy that only allows ingress from the load balancer.
- Drop kernel capabilities and use seccomp (Docker `--cap-drop=ALL --security-opt seccomp=...`, K8s `securityContext`).
- Monitor `parse_failures` and `unknown_sni` counters (currently a TODO: the `qsr_metrics_t` struct exists but is not yet wired into the dataplane).

## Known gaps

- No QUIC versions beyond v1 (RFC 9000) and v2 (RFC 9369). Other versions are dropped at the parser with `UNSUPPORTED`; the client falls back via version negotiation. We do not emit Version Negotiation packets in response.
- No ECH support: Encrypted ClientHello hides the SNI, making routing impossible by definition. Clients using ECH will fail to route.
- No NEW_CONNECTION_ID learning: CID rotation after the handshake is not visible because Handshake / 1-RTT packets are not decrypted (and never can be without terminating TLS, which we don't). The session breaks only when both (a) the NAT tuple rebinds AND (b) the client has rotated to a CID we never observed. Either alone is recoverable: only-NAT-rebinding hits the short-header CID lookup path; only-CID-rotation is invisible because we tuple-match. **Operational mitigation**: set the application's QUIC PING / keepalive interval below the expected NAT timeout (≤25s for cellular, ≤60s residential) — that prevents (a) and the CID rotation becomes harmless. **Architectural mitigation** (future): RFC 9484 QUIC-LB-encoded CIDs let the router route short-header packets statelessly by decoding a server-id from the DCID. See [ROADMAP.md](../ROADMAP.md).
- No retry-token issuance: the router cannot validate the client source IP before forwarding to the backend. The backend must enforce its own anti-amplification (QUIC stacks do this by default).
- Per-source rate limiting is not implemented in-process; rely on upstream controls.
