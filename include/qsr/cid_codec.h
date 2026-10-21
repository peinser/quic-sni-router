/*
 * qsr/cid_codec.h: authenticated-CID routing codec for stateless connection
 * migration. Backends generate server-issued connection IDs in the layout
 * documented below; the router decodes the destination CID of any short-header
 * 1-RTT packet and routes by the extracted server_id without needing to have
 * observed that CID during the QUIC handshake.
 *
 * Layout (fixed length QSR_CID_ENCODED_LEN = 20 bytes):
 *
 *   byte 0:    version marker QSR_CID_ENCODED_VERSION (plaintext, constant)
 *   bytes 1-7: per-CID nonce (plaintext, random per CID)
 *   byte 8:    server_id (plaintext, nonzero)
 *   bytes 9-19: first 11 bytes of HMAC-SHA256(key, bytes 0-8)
 *
 * The 88-bit tag authenticates the version, nonce, and routing field. This
 * format provides integrity, not server-id confidentiality or replay prevention.
 * The insecure 0x4f CTR format is deliberately not decoded.
 *
 * This is a qsr-specific format, not strict QUIC-LB compliance. It is shaped
 * to be easy to implement in arbitrary backend QUIC stacks and is documented
 * in docs/cid-routing.md with a Python reference generator.
 */
#ifndef QSR_CID_CODEC_H
#define QSR_CID_CODEC_H

#include "qsr/common.h"

#define QSR_CID_ENCODED_LEN 20U
#define QSR_CID_ENCODED_VERSION 0x50U
#define QSR_CID_KEY_LEN 16U
#define QSR_CID_NONCE_LEN 7U
#define QSR_CID_TAG_LEN 11U
#define QSR_CID_PAYLOAD_LEN (1U + QSR_CID_TAG_LEN)

typedef struct qsr_cid_codec {
  uint8_t key[QSR_CID_KEY_LEN];
  bool enabled;
} qsr_cid_codec_t;

/*
 * Initialize codec from a 32-character hex key (16 bytes AES-128).
 * On success the codec is marked enabled. On failure the struct is zeroed
 * and enabled = false.
 */
[[nodiscard]] qsr_status_t qsr_cid_codec_init_from_hex(qsr_cid_codec_t *codec, const char *hex_key);

/*
 * Encode a 20-byte CID containing the given server_id. nonce must point to
 * QSR_CID_NONCE_LEN random bytes; out must point to QSR_CID_ENCODED_LEN
 * writable bytes. server_id 0 is reserved and rejected.
 *
 * Primary consumer is the test suite and reference backends linked against
 * libqsr_core; production backends use the language-specific reference
 * generators in docs/cid-routing.md.
 */
[[nodiscard]] qsr_status_t qsr_cid_codec_encode(const qsr_cid_codec_t *codec, uint8_t server_id,
                                                const uint8_t nonce[QSR_CID_NONCE_LEN],
                                                uint8_t out[QSR_CID_ENCODED_LEN]);

/*
 * Try to decode a CID. Returns QSR_OK and writes the embedded server_id on
 * success; returns QSR_ERR_INVALID for any structural mismatch (wrong length,
 * wrong version byte, tag mismatch, server_id == 0). Designed to be cheap
 * and called on every short-header DCID.
 */
[[nodiscard]] qsr_status_t qsr_cid_codec_decode(const qsr_cid_codec_t *codec, const uint8_t *cid, size_t cid_len,
                                                uint8_t *server_id);

#endif
