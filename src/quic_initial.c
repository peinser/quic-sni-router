#include "qsr/quic_initial.h"

#include <string.h>

qsr_status_t qsr_quic_parse_varint(const uint8_t *data, size_t len, uint64_t *value, size_t *consumed) {
  if (data == nullptr || value == nullptr || consumed == nullptr || len == 0U) {
    return QSR_ERR_INVALID;
  }

  const uint8_t prefix = (uint8_t)(data[0] >> 6U);
  const size_t width = (size_t)1U << prefix;
  if (width > len) {
    return QSR_ERR_TRUNCATED;
  }

  uint64_t result = (uint64_t)(data[0] & 0x3fU);
  for (size_t i = 1U; i < width; i++) {
    result = (result << 8U) | data[i];
  }

  *value = result;
  *consumed = width;
  return QSR_OK;
}

qsr_status_t qsr_quic_parse_long_header(const uint8_t *data, size_t len, qsr_quic_long_header_t *out) {
  if (data == nullptr || out == nullptr) {
    return QSR_ERR_INVALID;
  }
  if (len < 7U) {
    return QSR_ERR_TRUNCATED;
  }
  /* Long header (bit 7 set) and fixed bit (bit 6 set) are version-independent. */
  if ((data[0] & 0x80U) == 0U || (data[0] & 0x40U) == 0U) {
    return QSR_ERR_INVALID;
  }

  qsr_quic_long_header_t parsed = {0};
  parsed.version = ((uint32_t)data[1] << 24U) | ((uint32_t)data[2] << 16U) | ((uint32_t)data[3] << 8U) | data[4];
  if (parsed.version != QSR_QUIC_V1 && parsed.version != QSR_QUIC_V2) {
    return QSR_ERR_UNSUPPORTED;
  }
  parsed.type_bits = data[0] & 0x30U;

  size_t offset = 5U;
  parsed.dcid_len = data[offset++];
  if (parsed.dcid_len > sizeof(parsed.dcid) || parsed.dcid_len > len - offset) {
    return QSR_ERR_INVALID;
  }
  if (parsed.dcid_len > 0U) {
    memcpy(parsed.dcid, data + offset, parsed.dcid_len);
  }
  offset += parsed.dcid_len;

  if (offset >= len) {
    return QSR_ERR_TRUNCATED;
  }
  parsed.scid_len = data[offset++];
  if (parsed.scid_len > sizeof(parsed.scid) || parsed.scid_len > len - offset) {
    return QSR_ERR_INVALID;
  }
  if (parsed.scid_len > 0U) {
    memcpy(parsed.scid, data + offset, parsed.scid_len);
  }
  offset += parsed.scid_len;
  parsed.remainder_offset = offset;

  *out = parsed;
  return QSR_OK;
}

/*
 * Long-header type bits (positions 4-5 of byte 0, masked with 0x30) encoding
 * "Initial" packet — differs between QUIC v1 and v2:
 *   v1 (RFC 9000): Initial=0b00, 0-RTT=0b01, Handshake=0b10, Retry=0b11.
 *   v2 (RFC 9369): Initial=0b01, 0-RTT=0b10, Handshake=0b11, Retry=0b00.
 *
 * Returns 0xFF for any version we don't support, so callers can distinguish
 * "wrong type bits for this version" (QSR_ERR_INVALID) from "unknown QUIC
 * version" (QSR_ERR_UNSUPPORTED).
 */
[[nodiscard]] static uint8_t expected_initial_type_bits(uint32_t version) {
  switch (version) {
    case QSR_QUIC_V1:
      return 0x00U;
    case QSR_QUIC_V2:
      return 0x10U;
    default:
      return 0xFFU;
  }
}

qsr_status_t qsr_quic_parse_initial(const uint8_t *data, size_t len, qsr_quic_initial_t *out) {
  if (data == nullptr || out == nullptr) {
    return QSR_ERR_INVALID;
  }
  qsr_quic_long_header_t header;
  qsr_status_t status = qsr_quic_parse_long_header(data, len, &header);
  if (status != QSR_OK) {
    return status;
  }

  /* Reject Retry/Handshake/0-RTT: only Initial advances to the deprotection path. */
  if (header.type_bits != expected_initial_type_bits(header.version)) {
    return QSR_ERR_INVALID;
  }

  qsr_quic_initial_t parsed = {0};
  parsed.version = header.version;
  parsed.dcid_len = header.dcid_len;
  parsed.scid_len = header.scid_len;
  memcpy(parsed.dcid, header.dcid, header.dcid_len);
  memcpy(parsed.scid, header.scid, header.scid_len);

  /* RFC 9000 17.2: peers MUST validate 8 <= DCID length on client Initials. */
  if (parsed.dcid_len < 8U) {
    return QSR_ERR_INVALID;
  }

  size_t offset = header.remainder_offset;
  uint64_t token_len = 0;
  size_t consumed = 0;
  status = qsr_quic_parse_varint(data + offset, len - offset, &token_len, &consumed);
  if (status != QSR_OK) {
    return status;
  }
  offset += consumed;
  if (token_len > (uint64_t)(len - offset)) {
    return QSR_ERR_TRUNCATED;
  }
  parsed.token_offset = offset;
  parsed.token_len = (size_t)token_len;
  offset += parsed.token_len;

  uint64_t payload_len = 0;
  status = qsr_quic_parse_varint(data + offset, len - offset, &payload_len, &consumed);
  if (status != QSR_OK) {
    return status;
  }
  offset += consumed;
  if (payload_len > (uint64_t)(len - offset)) {
    return QSR_ERR_TRUNCATED;
  }
  /*
   * Header-protection sampling requires at least 4 bytes of packet number plus
   * a 16-byte sample, and AES-GCM adds a 16-byte tag. Reject anything that
   * cannot possibly carry a valid protected Initial.
   */
  if (payload_len < QSR_MIN_INITIAL_PAYLOAD_LEN) {
    return QSR_ERR_INVALID;
  }

  parsed.packet_number_offset = offset;
  parsed.payload_offset = offset;
  parsed.payload_len = (size_t)payload_len;
  *out = parsed;
  return QSR_OK;
}
