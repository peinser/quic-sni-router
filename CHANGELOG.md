# Changelog

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project intends to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from 1.0 onward. Pre-1.0 releases may break wire-adjacent behaviour without a major bump.

## [Unreleased]

### Security

- Replaced FNV-1a with SipHash-2-4 in the session and route tables. A 16-byte hash key is seeded from `getrandom(2)` at process startup; an attacker controlling QUIC DCIDs or SNIs can no longer force open-addressed-table probe walks via collision crafting. RFC test vectors pinned in `tests/unit/test_hash.c`.
- Refused short single-CID aliases. `qsr_session_single_cid_key` returns an invalid key for CID lengths below `QSR_MIN_LEARNED_CID_LEN` (8, matching RFC 9000 §17.2 SHOULD); `lookup_short_header_cid` iterates from that floor. Closes a short-header false-match amplification vector where an attacker who established a connection with a 1- or 2-byte SCID could cause subsequent unrelated short-header packets to false-route at rate ≈ N_sessions / 256^len per try. Per-try probability at the new floor is ~5e-15 even at 100K sessions.
- `qsr_hash_bytes` now aborts on `getrandom` failure instead of returning a constant sentinel. The previous behaviour silently re-enabled the hash-flooding vector for the lifetime of the process; fail-hard is the correct response for a single irrecoverable condition.
- Tightened the ACK-frame `range_count` bound in `qsr_quic_extract_crypto` from `range_count > plaintext_len` to `range_count > (plaintext_len - offset) / 2`. Each range is ≥2 varint bytes, so the new bound matches the minimum encoding size and short-circuits CPU-burning loops before the varint parse.
- `qsr_config_load` rejects YAML scalars containing embedded NUL bytes. Operator config is trusted but the check is one `memchr` and removes a category of "prefix-matches-but-actually-evil" footguns from any future `strcmp` against parsed key/value strings.

### Changed

- Restructured `src/tls_client_hello.c` around a small `reader_t` abstraction with fail-fast typed reads (`r_u8` / `r_u16` / `r_u24` / `r_skip`) and length-prefixed sub-readers that physically cannot walk past their declared parent length. Replaces 14 hand-rolled `if (offset > end || N > end - offset)` checks with one bounds check per field. Same wire-level semantics; `QSR_ERR_TRUNCATED` vs `QSR_ERR_INVALID` is now reported more accurately (a too-short handshake header was previously conflated as INVALID — it's TRUNCATED).

### Performance

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
