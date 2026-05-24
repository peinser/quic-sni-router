# Changelog

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project intends to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from 1.0 onward. Pre-1.0 releases may break wire-adjacent behaviour without a major bump.

## [Unreleased]

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
