/*
 * qsr/quic_initial.h: long-header packet parsing for QUIC v1 (RFC 9000) and
 * v2 (RFC 9369). qsr_quic_parse_long_header reads version + CID fields from
 * any supported long-header packet, which is enough for Retry/CID learning.
 * qsr_quic_parse_initial then adds Initial-specific validation and reads token
 * and protected-payload offsets for decryption.
 *
 * Decryption lives in qsr/quic_crypto.h; frame walking lives in qsr/quic_frames.h.
 */
#ifndef QSR_QUIC_INITIAL_H
#define QSR_QUIC_INITIAL_H

#include "qsr/common.h"

typedef struct qsr_quic_initial {
  uint32_t version;
  uint8_t dcid[QSR_MAX_QUIC_CID_LEN];
  size_t dcid_len;
  uint8_t scid[QSR_MAX_QUIC_CID_LEN];
  size_t scid_len;
  size_t token_offset;
  size_t token_len;
  size_t payload_offset;
  size_t payload_len;
  size_t packet_number_offset;
} qsr_quic_initial_t;

typedef struct qsr_quic_long_header {
  uint32_t version;
  uint8_t type_bits;
  uint8_t dcid[QSR_MAX_QUIC_CID_LEN];
  size_t dcid_len;
  uint8_t scid[QSR_MAX_QUIC_CID_LEN];
  size_t scid_len;
  size_t remainder_offset;
} qsr_quic_long_header_t;

[[nodiscard]] qsr_status_t qsr_quic_parse_long_header(const uint8_t *data, size_t len,
                                                      qsr_quic_long_header_t *out);
[[nodiscard]] qsr_status_t qsr_quic_parse_initial(const uint8_t *data, size_t len, qsr_quic_initial_t *out);
[[nodiscard]] qsr_status_t qsr_quic_parse_varint(const uint8_t *data, size_t len, uint64_t *value, size_t *consumed);

#endif
