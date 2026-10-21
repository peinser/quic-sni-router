# Authenticated CID routing

This page describes the qsr-specific authenticated format. For interoperable
QUIC-LB wire formats, see [quic-lb.md](quic-lb.md). Select one mode per router;
the formats have different security properties and are not auto-detected.

`cidEncoding` lets cooperating backends encode a route's `serverId` in every
server-issued CID. The router can then route migration to an unobserved CID
without decrypting `NEW_CONNECTION_ID` frames. This is a qsr-specific format,
not QUIC-LB wire compatibility.

```yaml
cidEncoding:
  key: "00112233445566778899aabbccddeeff" # example only; generate your own 16-byte key
routes:
  example.test:
    host: backend.example.internal
    port: 8443
    serverId: 42
```

## Wire format (20 bytes)

| Bytes | Meaning |
|---|---|
| 0 | Version `0x50` |
| 1–7 | Seven-byte nonce |
| 8 | Server ID, 1–255 |
| 9–19 | First 11 bytes of HMAC-SHA256(key, bytes 0–8) |

All routing fields are authenticated with an 88-bit tag. Verification uses a
constant-time comparison. The server ID is public: this format provides routing
integrity, not confidentiality or client address validation. A valid CID can be
replayed; backends must still enforce QUIC authentication and anti-amplification.
Use a dedicated key, not a TLS or unrelated application's key.

Backends must avoid issuing duplicate nonces for a given server ID/key. Random
56-bit nonces have a birthday ceiling; use a coordinated unique allocator for
high-volume, long-lived deployments, and plan key rotation. Duplicate nonces do
not reveal the HMAC key, but duplicate CIDs can confuse backend connection lookup.

Python reference generator (standard library only):

```python
import hashlib
import hmac

def encode_cid(key: bytes, server_id: int, nonce: bytes) -> bytes:
    if len(key) != 16 or not 1 <= server_id <= 255 or len(nonce) != 7:
        raise ValueError("expected 16-byte key, nonzero byte ID, and 7-byte nonce")
    prefix = b"\x50" + nonce + bytes([server_id])
    return prefix + hmac.new(key, prefix, hashlib.sha256).digest()[:11]
```

## Upgrade and rotation

The old 16-byte `0x4f` AES-CTR format was malleable: changing its server-ID byte
did not invalidate its fixed magic. It is no longer decoded. There is no unsafe
compatibility fallback.

Upgrade routers and cooperating CID issuers together in a drained deployment.
Existing tuple-routed traffic can continue, but migration using old/old-key CIDs
is not guaranteed. Only one key is configured at a time; changing it can break
active migration, so drain before rotating. Backends must issue 20-byte CIDs and
use the same key and server IDs as their routers.

Encoded routing does not share flow state or preserve the upstream source port
when a different worker receives a packet. Load balancing and connection draining
still need deployment-level coordination.
