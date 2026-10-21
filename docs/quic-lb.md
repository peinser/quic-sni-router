# QUIC-LB wire interoperability

The router decodes the CID formats in
[draft-ietf-quic-load-balancers-21](https://www.ietf.org/archive/id/draft-ietf-quic-load-balancers-21.html),
sections 3 and 5. This revision is an expired Internet-Draft dated August 2025,
not a published RFC. Compatibility is pinned to this revision; deployments must
agree on the format and configuration with their backend QUIC implementation.

Supported wire formats:

- Unencrypted server ID followed by a nonce.
- Single-pass AES-128-ECB when server-ID length plus nonce length is 16 bytes.
- Four-pass AES-based Feistel encoding for every other legal length, including
  odd lengths and IDs spanning both halves. Decoding uses three passes when the
  complete ID is in the left half, otherwise four.
- Configuration IDs 0–6, independently configured and simultaneously active.
  Codepoint 7 is always unroutable.
- Server IDs of 1–15 bytes, nonces of at least 4 bytes, and a combined length
  no greater than 19 bytes. All-zero server IDs are valid.
- Optional appended CID bytes, up to QUIC's 20-byte CID limit. The low five
  first-octet bits may be random or self-describe length; the router uses the
  configured lengths, not those bits.

## Configuration

```yaml
listen:
  udp: ":8443"
quicLb:
  configurations:
    - id: 0
      serverIdLength: 3
      nonceLength: 4
      key: "8f95f09245765f80256934e50c66207f" # published test key; use your own
    - id: 1
      serverIdLength: 3
      nonceLength: 8
      key: "00112233445566778899aabbccddeeff"
routes:
  example.test:
    host: backend-worker-1.internal
    port: 8443
    quicLbServerIds:
      "0": "ed793a"
      "1": "ed793a"
```

IDs are byte strings encoded as hexadecimal, not integers. Quote them to preserve
leading zeros through YAML/Helm tooling. Each mapping key selects a configuration
ID. Its value must contain exactly that configuration's `serverIdLength` bytes.
Mappings are independent between configurations: the same ID may route to a
different endpoint under another configuration. Within one configuration an ID
must have one route. Additional SNI aliases for the same endpoint can omit the
CID mapping and use that endpoint's canonical route mapping.

Omitting `key` selects the draft's unencrypted format. An empty or malformed key
is an error. Duplicate configurations, duplicate mappings, mismatched ID lengths,
unknown fields, and configurations with no mapped route are rejected. Configuration
and route order in the YAML file does not matter.

`quicLb` and the qsr-specific `cidEncoding` mode are mutually exclusive. Use
`quicLbServerIds` here; the old numeric `serverId` is for `cidEncoding` only.
This avoids guessing between overlapping wire formats.

## Routing and rotation

A successfully decoded ID that maps to a configured backend takes precedence
over tuple state, for both short and long headers. It can therefore route an
unobserved server CID after NAT rebinding or CID rotation. Long-header extraction
uses the QUIC invariant fields, even for unknown versions and without assuming
the version-specific fixed bit.

If a CID is unroutable, qsr retains its existing SNI/session fallback policy:
known state can route packets; unknown v1/v2 Initials can route through SNI;
unknown unsupported-version traffic is dropped. This is **wire-format
interoperability**, not a claim to implement every generic load-balancer forwarding
requirement in draft section 4 (in particular, its tuple-only baseline fallback).
The existing per-client-tuple flow model and bounded ClientHello buffering remain.

For key/length rotation:

1. Add a new unused configuration ID and its route mappings on every router,
   retaining the old configuration and mappings.
2. Reload routers, then configure backends to issue CIDs under the new ID.
3. Retain the old configuration until its CIDs have been retired or their
   connections have ended; only then remove it.

Do not replace the key or lengths of a still-used configuration ID in place.
Reload publishes the decoder parameters and mapping indexes together. Removing
a configuration stops stateless recovery for its CIDs; existing tuple state may
still forward them, but that is not a migration guarantee. Removing a backend
continues to close its flows under the existing hard-cutover policy.

## Security and workers

QUIC-LB encryption provides privacy, **not CID authentication**. Any sufficiently
long ciphertext under an active configuration decodes to some server ID. Unknown
IDs fall back to ordinary routing; an ID that happens to be assigned routes to
that backend, even in a client-generated Initial. Use a sparse ID space (for
example three or more bytes), and retain backend TLS/QUIC authentication and
anti-amplification. CIDs are routing hints, not authorization credentials. The
unencrypted mode exposes server IDs and makes selecting a backend trivial.

A mapping may point to an individually addressable backend worker endpoint.
Workers sharing an identical IP/port must perform their own demultiplexing.
This implementation does not steer packets between router processes, share
flow/socket ownership, or preserve upstream ports after worker replacement.
CID-aware router-worker steering is a separate architectural task.

## Verification

`tests/unit/test_quic_lb.c` checks the encrypted Appendix B vectors and the
section 5.4.2.4 example, plus unencrypted, truncation, rotation, and mapping cases.
The draft has transcription errors: Appendix B.1's second row has odd-length hex,
and B.2's last row labels config 3 although its first octet `0x12` means config 0.
Tests use valid wire bytes, corroborated by
[QUICHE's decoder vectors](https://github.com/google/quiche/blob/main/quiche/quic/load_balancer/load_balancer_decoder_test.cc),
and cover both sides of the odd-length split. Packet tests cover precedence,
rebinding, opaque forwarding, unknown versions, and reload publication.

`make fuzz-smoke` includes a dedicated QUIC-LB decoder fuzzer covering all decoder
branches and length limits.
