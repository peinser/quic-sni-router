# Protocol Notes

`quic-sni-router` supports a fixed allowlist of QUIC versions: v1 (RFC 9000, version `0x00000001`) and v2 (RFC 9369, version `0x6b3343cf`). For both, the implementation parses long-header Initial packets, derives client Initial secrets from the destination connection ID and the version-specific salt, removes header protection, decrypts the Initial payload, extracts CRYPTO frames, and parses TLS ClientHello SNI with bounded reads.

Initial deprotection uses OpenSSL libcrypto HKDF (SHA-256), AES-128-ECB for QUIC header protection mask generation, and AES-128-GCM for packet protection. This is unavoidable: both QUIC versions encrypt the TLS ClientHello inside Initial CRYPTO frames. The router forwards original datagrams unchanged after SNI lookup and never holds private keys.

## v1 vs v2 differences handled

| Element | v1 (RFC 9000/9001) | v2 (RFC 9369) |
| --- | --- | --- |
| Version number | `0x00000001` | `0x6b3343cf` |
| Initial salt | `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a` | `0x0dede3def700a6db819381be6e269dcbf9bd2ed9` |
| Long-header type bits for Initial | `0b00` (`0x00`) | `0b01` (`0x10`) |
| HKDF labels | `"quic key"`, `"quic iv"`, `"quic hp"` | `"quicv2 key"`, `"quicv2 iv"`, `"quicv2 hp"` |

The parser reads the version field first, then validates the type bits against that version's table. A v2-versioned packet with v1 type bits (or vice versa) is rejected as `INVALID` rather than fed to the wrong deprotection path. Any other version returns `UNSUPPORTED` (clients will then fall back via version negotiation).

Key derivation is validated against the published Appendix A test vectors in both RFCs (see [tests/unit/test_quic_crypto.c](../tests/unit/test_quic_crypto.c)).

## Validation applied before any crypto

A datagram that fails any of these checks is dropped without HKDF/AES work:

- Long header bit set, fixed bit set, type bits == Initial (0b00).
- Version == QUIC v1 (`0x00000001`).
- DCID length >= 8 (per RFC 9000 §7.2 routing guidance).
- DCID/SCID lengths fit inside the datagram.
- Token length and payload length fit inside the datagram.
- Payload length >= 36 bytes (4-byte assumed packet number + 16-byte HP sample + 16-byte AEAD tag).
- Datagram length >= 1200 bytes when the packet does not match any existing session (RFC 9000 §14.1).

The 1200-byte minimum is the cheapest available anti-reflection defense: a 100-byte forged Initial cannot become a 1500-byte forwarded datagram to a backend.

## CRYPTO frame reassembly

The CRYPTO extractor accepts the frame types legal in Initial space:

- `0x00` PADDING - skipped.
- `0x01` PING - skipped.
- `0x02`/`0x03` ACK / ACK_ECN - parsed to advance past the frame, contents not used.
- `0x06` CRYPTO - data is copied into the reassembly buffer at the indicated offset.

Anything else returns `QSR_ERR_UNSUPPORTED` and the datagram is dropped. The reassembly buffer is bounded at `QSR_MAX_CLIENT_HELLO_SIZE` (8 KiB) - a real ClientHello, even with the QUIC `quic_transport_parameters` extension, fits comfortably below this.

## Session pinning and rebinding

- Tuple alias (client `(addr,port)` -> backend) is the fast path.
- Long-header DCID, SCID, and (DCID, SCID) pair aliases are learned from every Initial in both directions, so a NAT rebinding that lands on a learned CID can recover the session.
- Short-header rebinding is best-effort: QUIC short headers do not self-describe the DCID length, so the router tries learned CID-length candidates from longest to shortest. On match, **both** the new client->backend mapping and the reverse backend->client mapping are updated atomically. (An earlier implementation forgot the reverse update and silently black-holed reply traffic - the test `test_expire_preserves_probe_chain` is part of the regression net.)
- Idle expiry uses `CLOCK_MONOTONIC` so an NTP step does not prematurely kill or indefinitely extend sessions.
- The session table uses open-addressing with backward-shift deletion. Expiry runs in-place; there is no rebuild step.
- When the table is at capacity the oldest entry (by `last_seen`) is evicted to make room. This trades some session loss for resistance to a fill-the-table DoS.

## Things the router intentionally does not do

- Version negotiation: only v1 and v2 are accepted; any other version is dropped at the parser. (We do not send Version Negotiation packets in response — clients drive the fallback on the timeout.)
- Retry: the router does not issue Retry tokens, so the backend is responsible for QUIC anti-amplification (every modern QUIC stack does this by default).
- Encrypted ClientHello (ECH): ECH hides the SNI by design and prevents SNI-based routing.
- 0-RTT, Handshake, 1-RTT decryption: the router never derives anything beyond client Initial keys.
- Backend address re-resolution: hostnames are resolved once at startup. To pick up a backend IP change, restart the process (or roll the pods).

## Dataplane

- Linux: nonblocking UDP socket on `epoll`, batched `recvmmsg` for receive and `sendmmsg` for send. Up to 32 datagrams per syscall.
- Other platforms: portable blocking `recvfrom`/`sendto` fallback.

`io_uring` was prototyped but the path served `submit; wait_cqe` per packet and was strictly slower than `recvmmsg` + `sendmmsg`. It has been removed; a future async-batched rewrite (multishot recv, registered buffers) is the right way to revisit.
