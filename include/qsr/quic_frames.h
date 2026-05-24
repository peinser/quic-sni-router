/*
 * qsr/quic_frames.h: frame walker for the plaintext of a deprotected QUIC
 * Initial packet. Reassembles CRYPTO frames (offset-keyed) into a single
 * buffer so the TLS ClientHello can be parsed by qsr/tls_client_hello.h.
 *
 * Skips PADDING (0x00), PING (0x01), and ACK (0x02, 0x03) frames — all of
 * which are legal in Initial space per RFC 9000 §17.2.2. Anything else
 * returns QSR_ERR_UNSUPPORTED.
 */
#ifndef QSR_QUIC_FRAMES_H
#define QSR_QUIC_FRAMES_H

#include "qsr/common.h"

typedef struct qsr_crypto_stream {
  uint8_t data[QSR_MAX_CLIENT_HELLO_SIZE];
  size_t len;
} qsr_crypto_stream_t;

void qsr_crypto_stream_init(qsr_crypto_stream_t *stream);
qsr_status_t qsr_quic_extract_crypto(const uint8_t *plaintext, size_t plaintext_len, qsr_crypto_stream_t *stream);

#endif
