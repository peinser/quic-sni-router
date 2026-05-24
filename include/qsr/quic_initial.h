/*
 * qsr/quic_initial.h: long-header Initial packet parsing for QUIC v1
 * (RFC 9000) and v2 (RFC 9369). Reads header fields (version, DCID, SCID,
 * token, payload offset/length) into qsr_quic_initial_t without decrypting.
 * Strict: rejects non-Initial type bits per the packet's announced version,
 * undersized payloads, and DCIDs shorter than 8 bytes (RFC 9000 §7.2).
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

[[nodiscard]] qsr_status_t qsr_quic_parse_initial(const uint8_t *data, size_t len, qsr_quic_initial_t *out);
[[nodiscard]] qsr_status_t qsr_quic_parse_varint(const uint8_t *data, size_t len, uint64_t *value, size_t *consumed);

#endif
