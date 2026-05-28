/*
 * qsr/cid_codec.h: encrypted-CID routing codec for stateless connection
 * migration. Backends generate server-issued connection IDs in the layout
 * documented below; the router decodes the destination CID of any short-header
 * 1-RTT packet and routes by the extracted server_id without needing to have
 * observed that CID during the QUIC handshake.
 *
 * Layout (fixed length QSR_CID_ENCODED_LEN = 16 bytes):
 *
 *   byte 0:    version marker QSR_CID_ENCODED_VERSION (plaintext, constant)
 *   bytes 1-7: per-CID nonce (plaintext, random per CID)
 *   bytes 8-15: AES-128-CTR(key, IV=byte0||nonce||zeros[8], plaintext) where
 *               plaintext = server_id (1 byte) || magic "qsrlrtr" (7 bytes)
 *
 * The plaintext magic gates routing: a random 16-byte CID has only a 1/2^64
 * chance of decoding to a server_id that passes the magic check, so the
 * codec is safe to attempt against every short-header DCID without false-
 * positive routing on attacker-supplied bytes. AES-CTR is keyed, so an
 * attacker cannot forge a CID that decodes to a chosen server_id without
 * the shared key.
 *
 * This is a qsr-specific format, not strict QUIC-LB compliance. It is shaped
 * to be easy to implement in arbitrary backend QUIC stacks (one AES-CTR call
 * over 8 bytes) and is documented in docs/cid-routing.md with reference
 * generators in Python and Go.
 */
#ifndef QSR_CID_CODEC_H
#define QSR_CID_CODEC_H

#include "qsr/common.h"

#define QSR_CID_ENCODED_LEN 16U
#define QSR_CID_ENCODED_VERSION 0x4fU
#define QSR_CID_KEY_LEN 16U
#define QSR_CID_NONCE_LEN 7U
#define QSR_CID_PAYLOAD_LEN 8U

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
 * Encode a 16-byte CID containing the given server_id. nonce must point to
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
 * wrong version byte, magic mismatch, server_id == 0). Designed to be cheap
 * and called on every short-header DCID.
 */
[[nodiscard]] qsr_status_t qsr_cid_codec_decode(const qsr_cid_codec_t *codec, const uint8_t *cid, size_t cid_len,
                                                uint8_t *server_id);

#endif
