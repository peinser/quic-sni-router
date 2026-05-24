/*
 * qsr/quic_crypto.h: QUIC Initial packet deprotection (header protection
 * removal + AES-128-GCM payload decryption) for QUIC v1 (RFC 9001) and v2
 * (RFC 9369). Picks the version-appropriate salt and HKDF labels (`quic`
 * vs `quicv2`). All inputs are derived from public information (DCID +
 * version-specific salt); no private key material handled.
 *
 * qsr_quic_initial_client_keys is exposed for unit tests that pin the
 * derivation against the published RFC test vectors.
 */
#ifndef QSR_QUIC_CRYPTO_H
#define QSR_QUIC_CRYPTO_H

#include "qsr/common.h"
#include "qsr/quic_initial.h"

typedef struct qsr_quic_plaintext {
  uint8_t data[QSR_MAX_CLIENT_HELLO_SIZE];
  size_t len;
} qsr_quic_plaintext_t;

/*
 * Client-side Initial packet protection keys for a single connection. All
 * three fields are derived from public information (the client's DCID, the
 * version-specific salt, and the version-specific HKDF labels) and carry no
 * private key material.
 */
typedef struct qsr_initial_keys {
  uint8_t key[16]; /* AES-128-GCM packet protection key */
  uint8_t iv[12];  /* AES-128-GCM nonce IV (XORed with packet number) */
  uint8_t hp[16]; /* AES-128-ECB header protection key */
} qsr_initial_keys_t;

/*
 * Derive client-side Initial keys for a given QUIC version and DCID. Exposed
 * for unit tests against the RFC 9001 / RFC 9369 Appendix A vectors; the
 * production decrypt path calls it internally.
 */
[[nodiscard]] qsr_status_t qsr_quic_initial_client_keys(uint32_t version, const uint8_t *dcid, size_t dcid_len,
                                                        qsr_initial_keys_t *out);

[[nodiscard]] qsr_status_t qsr_quic_decrypt_initial(const uint8_t *packet, size_t packet_len,
                                                    const qsr_quic_initial_t *initial, qsr_quic_plaintext_t *out);

#endif
