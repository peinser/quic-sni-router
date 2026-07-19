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

- Long header bit set and fixed bit set.
- Version is QUIC v1 (`0x00000001`) or QUIC v2 (`0x6b3343cf`).
- Type bits match that version's Initial encoding: v1 `0b00`, v2 `0b01`.
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

If a fresh client Initial decrypts cleanly but does not yet contain enough contiguous CRYPTO bytes to read SNI, the router keeps a bounded pending entry keyed by source tuple plus Initial DCID/SCID. Later Initial datagrams for that key are merged into the same CRYPTO stream; once SNI is available, all buffered original datagrams are forwarded unchanged to the selected backend. Pending entries are capped at 64 concurrent entries, 8 datagrams per entry, 1500 bytes per datagram, and expire after 5 seconds of inactivity.

## Session pinning, flows, and rebinding

- Each client tuple gets a **flow**: a dedicated unconnected UDP socket toward its backend. The backend therefore sees one router source port per client, and its return datagrams arrive on the flow's own fd. Return-path demultiplexing is exact (the fd identifies the client) for any number of concurrent QUIC connections to the same backend, including clients that use zero-length connection IDs or rotate CIDs after the handshake. The client side never sees this: forwarded backend packets are always sent from the listen socket, so the client's peer tuple stays the router's `:443`.
- Tuple alias (client `(addr,port)` -> backend) is the fast path for client-to-backend classification.
- Long-header DCID and (DCID, SCID) pair aliases are learned from client Initials, and the server-chosen SCID is learned from backend long-header responses (Initial, Handshake, Retry). A NAT rebinding that lands on a learned CID can recover the session; backend return traffic needs no CID inspection at all.
- Short-header rebinding is best-effort: QUIC short headers do not self-describe the DCID length, so the router tries learned CID-length candidates from longest to shortest. On match the new client tuple is bound to the backend, and the next client packet flows through a fresh upstream socket (the backend sees a path migration and validates it per RFC 9000 section 9).
- Idle expiry uses `CLOCK_MONOTONIC` so an NTP step does not prematurely kill or indefinitely extend sessions.
- The session table uses open-addressing with backward-shift deletion. Expiry runs in-place; there is no rebuild step. The flow table is slot-stable (epoll carries slot indices) with the same probe-cluster reinsertion on delete.
- When either table is at capacity the oldest entry (by `last_seen`) is evicted to make room. This trades some session loss for resistance to a fill-the-table DoS. Flow sockets are also recycled LRU-style when the process hits its fd limit.

### Fresh connection flow

```text
1. Client sends QUIC Initial to router

   client_ip:client_port
          |
          | UDP datagram: long header, DCID=C1, SCID=C2, encrypted ClientHello(SNI)
          v
   quic-sni-router
          |
          | parse Initial header
          | decrypt Initial only far enough to read TLS ClientHello SNI
          | lookup SNI -> backend_ip:443
          | learn aliases:
          |   client tuple              -> backend
          |   (DCID=C1, SCID=C2)        -> backend
          |   single DCID C1            -> backend
          | open per-client flow socket (router ephemeral port)
          v
   backend_ip:443

2. Backend sends Initial / Handshake packets back

   backend_ip:443
          |
          | UDP datagram: DCID=C2 (client's SCID)
          v
   quic-sni-router (this client's flow socket)
          |
          | the receiving fd identifies the client; no lookup
          | learn server SCID -> backend (for later NAT rebinding)
          v
   client_ip:client_port  (sent from the router's :443 listen socket)
```

The important part is step 2. A backend's UDP tuple is shared by all connections to that backend, so nothing in the packet has to identify the client; the per-client flow socket does. This also covers the packets that carry no routable bits at all: short-header packets toward clients with zero-length connection IDs, packets using post-handshake rotated CIDs (NEW_CONNECTION_ID is encrypted and invisible to the router), and stateless resets, which are intentionally indistinguishable from random short-header packets. `make test-e2e-flows` asserts the isolation property with two concurrent clients on one backend; `make test-e2e-reverse` covers the post-idle reset path.

For day-to-day troubleshooting, enable `logging.connections: true` in the router config (hot-reloadable, available in all builds). It logs one line per backend flow establishment (`conn: open src=... sni=... scid=... backend=...`) and one per teardown (`conn: close ... reason=idle|evicted|reload|shutdown|reroute|error duration=...s`), which is enough to correlate a frontend client tuple with its backend session without per-packet volume. The `scid` is the client's Initial SCID when the flow was routed by SNI, `-` when the flow was re-established from learned session state.

For deeper production diagnosis, deploy the matching `-debug` image tag and set `QSR_DEBUG_PACKETS=1` on the router pod. It logs one line per forwarded/dropped packet with packet kind, source tuple, backend-source classification, selected destination, and routing decision (`fresh_sni`, `tuple`, `short_cid_rebind`, `drop_initial_route`, etc.). Default images compile this packet logging path out entirely; debug images compile it in but stay quiet unless the environment variable is enabled. Do not leave packet logging enabled under normal traffic volume.

### Established short-header flow

```text
client tuple hit:

   client_ip:client_port -> backend_ip:443
          |
          v
   forward datagram unchanged

backend return packet:

   backend_ip:443
          |
          | arrives on this client's flow socket
          v
   fd -> client tuple (no parsing, no table lookup)
          |
          v
   forward datagram unchanged from the :443 listen socket
```

The router does not decrypt Handshake or 1-RTT packets. It only uses visible QUIC header CIDs plus the learned tuple aliases.

### NAT rebinding flow

```text
original client tuple: 198.51.100.10:53000 -> backend
new client tuple:      198.51.100.10:61000 -> router

new short-header packet arrives from 198.51.100.10:61000
          |
          | tuple miss
          | CID lookup hits existing session
          v
router installs:
          |
          | 198.51.100.10:61000 -> backend
          | backend -> 198.51.100.10:61000
          v
session continues
```

This recovery only works while the packet carries a CID the router has learned. CID rotation after the handshake is opaque to the router unless the client tuple remains stable. Note this only constrains the client-to-backend direction: backend return traffic is fd-routed per flow and is immune to CID rotation.

### Two fixed loadtest bugs

```text
source-port reuse bug:

old connection: client A tuple -> backend A
kernel reuses same client tuple for fresh connection to backend B
fresh Initial arrives
old behaviour: tuple hit -> backend A        (wrong)
new behaviour: Initial pair-CID lookup first; stale forward tuple ignored; route by SNI

backend reverse tuple bug:

client A -> backend X
client B -> backend X
backend X has one UDP tuple
old behaviour: backend tuple -> whichever client wrote last       (ambiguous)
intermediate:  backend packets use learned DCID -> correct client (fails for
               zero-length or rotated client CIDs)
new behaviour: per-client upstream flow sockets; the receiving fd IS the
               demux key, no CID needed
```

## Things the router intentionally does not do

- Version negotiation: only v1 and v2 are accepted; any other version is dropped at the parser. (We do not send Version Negotiation packets in response — clients drive the fallback on the timeout.)
- Retry: the router does not issue Retry tokens, so the backend is responsible for QUIC anti-amplification (every modern QUIC stack does this by default).
- Encrypted ClientHello (ECH) inner-hostname routing: ECH encrypts the real SNI in an inner ClientHello, leaving only an outer cover hostname visible. The router routes by whatever SNI is in the outer ClientHello — so ECH-using clients reach whichever backend the cover hostname points at, never the real inner hostname. Recovering the inner SNI requires TLS termination, which we do not do. Detecting ECH presence and emitting an observability counter is in [ROADMAP.md](../ROADMAP.md).
- 0-RTT, Handshake, 1-RTT decryption: the router never derives anything beyond client Initial keys.
- Backend address re-resolution: hostnames are resolved once at startup. To pick up a backend IP change, restart the process (or roll the pods).

## Dataplane

- Linux: nonblocking sockets on one `epoll` set (listen socket + one upstream socket per flow + inotify), batched `recvmmsg` for receive and `sendmmsg` for send. The send batcher groups consecutive same-fd datagrams so a GRO burst still leaves as one syscall even across per-flow sockets.
- Linux listen-socket receive/send buffers are raised best-effort to 4 MiB. The kernel may clamp this to `net.core.rmem_max` / `net.core.wmem_max`. Flow sockets keep kernel defaults.
- `RLIMIT_NOFILE` is raised to the hard limit at startup; if it still cannot cover the flow table (sized at `maxSessions / 4`), a startup warning explains that excess concurrency degrades to LRU flow recycling.
- Other platforms: portable nonblocking `poll()` + `recvfrom`/`sendto` fallback (development path).

## Current performance considerations

- Fresh handshakes are the expensive path because the router must perform Initial header protection removal, AES-GCM decrypt, CRYPTO frame extraction, TLS ClientHello parsing, SNI lookup, and several session-table inserts.
- Established sessions are much cheaper: client-to-backend is one tuple lookup plus a flow lookup and datagram forwarding, no crypto; backend-to-client is fd dispatch with zero table lookups (plus a two-bit header peek for SCID learning).
- Configured-backend checks use the route table's resolved backend-address index, so they are bounded hash lookups rather than route-count scans.
- Short-header CID lookup tries possible CID lengths from longest down to `QSR_MIN_LEARNED_CID_LEN`. It only runs on client tuple misses (NAT rebinds), and skips lengths never learned.

`io_uring` was prototyped but the path served `submit; wait_cqe` per packet and was strictly slower than `recvmmsg` + `sendmmsg`. It has been removed; a future async-batched rewrite (multishot recv, registered buffers) is the right way to revisit.
