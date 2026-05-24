# Implementation Inspirations

This project can borrow operating principles from TCP SNI routers, but the dataplane must remain QUIC-specific.

## dlundquist/sniproxy

Useful ideas:

- Separate listener, protocol parser, routing table, and forwarding code.
- Fail closed when the initial client request cannot produce a trusted hostname.
- Keep private keys and certificate material out of the proxy process.
- Treat DNS-backed routes and hot route changes as operational concerns separate from parsing.

Not directly portable:

- `sniproxy` is TCP-stream based; QUIC requires UDP session pinning and packet-oriented forwarding.
- HTTP/2 and HTTP/3 multiplexing caveats differ; this router keys only on QUIC Initial ClientHello SNI.

## AGWA/snid

Useful ideas:

- Minimal proxy surface area.
- Backend address derivation and backend CIDR constraints are worth considering for a future route mode.
- Default-hostname/fallback behavior should be explicit; the current safer default is to drop unknown or SNI-less traffic.

Not directly portable:

- `snid` is TCP/TLS oriented and can use connection lifetime as the routing unit.
- QUIC return traffic must be associated with client tuple/CIDs and idle-expired explicitly.

## HyBuildNet/quic-relay

Useful ideas:

- QUIC-specific SNI routing can share one UDP listener across multiple backend services.
- A handler-chain architecture (Continue / Handled / Drop) is a useful model for future optional policy stages such as logging, rate limiting, and route selection.
- Round-robin load balancing across multiple backend addresses per route is a reasonable next step; QUIC connections still need to pin to a stable backend endpoint for the lifetime of the connection.
- In-process rate limiting (their `ratelimit-global` handler) is a complement to upstream BCP 38 / cloud LB controls when a single-tenant operator wants a cheap CPU-DoS shield without a separate L4 box. This project currently defers all rate limiting to upstream; see [threat-model.md](threat-model.md).
- Published deployment docs make the TLS termination tradeoff explicit, which is valuable for operators comparing pass-through and terminating modes.

Not directly portable:

- `quic-relay` is Hytale-oriented and includes optional QUIC TLS termination for protocol inspection/manipulation; this project intentionally keeps private keys out of the router and leaves TLS/mTLS termination in backend pods.
- Its terminating mode creates separate client-side and backend-side QUIC/TLS connections; this router forwards original datagrams unchanged after SNI lookup.
- Its Go `quic-go` architecture is a full QUIC stack when terminating, while this project only derives client Initial keys far enough to recover ClientHello SNI.
- Session pinning in `quic-relay` appears to be implicit (idle-timeout cleanup of UDP flows); this project additionally learns observed Initial DCID/SCID and pair-CID aliases so a NAT rebinding can recover the session without a re-handshake.
- `quic-relay` does not document QUIC v2 (RFC 9369) support; this project explicitly accepts both v1 and v2 Initials and validates the version-specific Initial type bits before deprotection.
