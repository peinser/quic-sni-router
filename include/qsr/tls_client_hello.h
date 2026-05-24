/*
 * qsr/tls_client_hello.h: TLS 1.3 ClientHello SNI extractor. Bounded-read
 * parser: walks ClientHello -> extensions -> server_name extension and
 * returns the first host_name entry. Validates the hostname (lowercase
 * ASCII DNS, no leading hyphen, no empty labels, ≤255 chars) before
 * returning it for route lookup.
 *
 * Operates on the CRYPTO-frame plaintext produced by qsr/quic_frames.h.
 */
#ifndef QSR_TLS_CLIENT_HELLO_H
#define QSR_TLS_CLIENT_HELLO_H

#include "qsr/common.h"

typedef struct qsr_sni {
  char name[QSR_MAX_HOSTNAME_LEN + 1U];
} qsr_sni_t;

[[nodiscard]] qsr_status_t qsr_tls_client_hello_sni(const uint8_t *data, size_t len, qsr_sni_t *out);

#endif
