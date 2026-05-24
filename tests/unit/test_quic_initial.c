#include "qsr/quic_initial.h"
#include "test_main.h"

#include <string.h>

static void test_parse_initial_happy_path(void) {
  /*
   * Long header + fixed bit + Initial type, QUIC v1, 8-byte DCID,
   * 4-byte SCID, empty token, payload_len = 60 (variable-length-encoded as
   * 0x40 0x3c since it is >= 64-1 ... actually 60 fits in 6 bits so 0x3c).
   * Bytes after the payload-length varint are header-protected packet number
   * + ciphertext; we do not parse those here, just verify offsets/lengths.
   */
  uint8_t packet[5U + 1U + 8U + 1U + 4U + 1U + 1U + 60U] = {
      0xc3, 0x00, 0x00, 0x00, 0x01,             /* type + version */
      0x08, 1, 2, 3, 4, 5, 6, 7, 8,             /* dcid_len + dcid */
      0x04, 9, 10, 11, 12,                      /* scid_len + scid */
      0x00,                                     /* token_len varint = 0 */
      0x3c,                                     /* payload_len varint = 60 */
  };
  qsr_quic_initial_t initial;
  ASSERT_TRUE(qsr_quic_parse_initial(packet, sizeof(packet), &initial) == QSR_OK);
  ASSERT_TRUE(initial.version == QSR_QUIC_V1);
  ASSERT_TRUE(initial.dcid_len == 8U);
  ASSERT_TRUE(initial.scid_len == 4U);
  ASSERT_TRUE(initial.payload_len == 60U);
}

static void test_parse_v2_initial_happy_path(void) {
  /* QUIC v2 (RFC 9369): Initial type bits are 0b01 (= 0x10 in byte 0), version
   * 0x6b3343cf. Same wire layout as v1 otherwise. */
  uint8_t packet[5U + 1U + 8U + 1U + 4U + 1U + 1U + 60U] = {
      0xd3, 0x6b, 0x33, 0x43, 0xcf,             /* long+fixed+Initial(v2), version v2 */
      0x08, 1, 2, 3, 4, 5, 6, 7, 8,
      0x04, 9, 10, 11, 12,
      0x00,
      0x3c,
  };
  qsr_quic_initial_t initial;
  ASSERT_TRUE(qsr_quic_parse_initial(packet, sizeof(packet), &initial) == QSR_OK);
  ASSERT_TRUE(initial.version == QSR_QUIC_V2);
  ASSERT_TRUE(initial.dcid_len == 8U);
  ASSERT_TRUE(initial.payload_len == 60U);
}

static void test_parse_rejects_v2_packet_with_v1_type_bits(void) {
  /*
   * Defense in depth: a packet that announces version v2 but uses v1's Initial
   * type bits (0b00) is actually a v2 Retry packet — not an Initial. We must
   * not feed it to the Initial deprotection path.
   */
  uint8_t packet[26] = {0xc3, 0x6b, 0x33, 0x43, 0xcf, 0x08, 1, 2, 3, 4, 5,
                        6,    7,    8,    0x04, 9,    10,   11, 12, 0x00, 0x3c};
  qsr_quic_initial_t initial;
  ASSERT_TRUE(qsr_quic_parse_initial(packet, sizeof(packet), &initial) == QSR_ERR_INVALID);
}

static void test_parse_rejects_v1_packet_with_v2_type_bits(void) {
  /* And the inverse: a v1-versioned packet with v2 Initial type bits is a v1
   * 0-RTT (0b01) packet that we cannot decrypt. */
  uint8_t packet[26] = {0xd3, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3, 4, 5,
                        6,    7,    8,    0x04, 9,    10,   11, 12, 0x00, 0x3c};
  qsr_quic_initial_t initial;
  ASSERT_TRUE(qsr_quic_parse_initial(packet, sizeof(packet), &initial) == QSR_ERR_INVALID);
}

static void test_parse_initial_rejects_invalid_fixed_bit(void) {
  uint8_t packet[60] = {0x83, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x00, 0x3c};
  qsr_quic_initial_t initial;
  ASSERT_TRUE(qsr_quic_parse_initial(packet, sizeof(packet), &initial) == QSR_ERR_INVALID);
}

static void test_parse_initial_rejects_non_initial_type(void) {
  /* 0-RTT: type bits 0b01 in [4:5] */
  uint8_t packet[60] = {0xd3, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x00, 0x3c};
  qsr_quic_initial_t initial;
  ASSERT_TRUE(qsr_quic_parse_initial(packet, sizeof(packet), &initial) == QSR_ERR_INVALID);
}

static void test_parse_initial_rejects_short_dcid(void) {
  /* RFC 9000 §7.2: routers SHOULD treat DCID < 8 on client Initials as invalid. */
  uint8_t packet[60] = {0xc3, 0x00, 0x00, 0x00, 0x01, 0x04, 1, 2, 3, 4, 0x00, 0x00, 0x3c};
  qsr_quic_initial_t initial;
  ASSERT_TRUE(qsr_quic_parse_initial(packet, sizeof(packet), &initial) == QSR_ERR_INVALID);
}

static void test_parse_initial_rejects_undersized_payload(void) {
  /* payload_len = 5 is below the QSR_MIN_INITIAL_PAYLOAD_LEN (36 bytes) floor. */
  uint8_t packet[26] = {0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3, 4, 5,
                        6,    7,    8,    0x04, 9,    10,   11, 12, 0x00, 0x05,
                        0x00, 0x00, 0x00, 0x00, 0x00};
  qsr_quic_initial_t initial;
  ASSERT_TRUE(qsr_quic_parse_initial(packet, sizeof(packet), &initial) == QSR_ERR_INVALID);
}

static void test_parse_initial_rejects_unknown_version(void) {
  /* A version that is neither v1 nor v2 — for example the IETF "force version
   * negotiation" draft greasing pattern 0x0a0a0a0a. We must return UNSUPPORTED
   * (distinguishable from INVALID, so callers can log "new version observed"
   * without losing the actual-malformed-packet signal). */
  uint8_t packet[26] = {0xc3, 0x0a, 0x0a, 0x0a, 0x0a, 0x08, 1, 2, 3, 4, 5,
                        6,    7,    8,    0x04, 9,    10,   11, 12, 0x00, 0x3c};
  qsr_quic_initial_t initial;
  ASSERT_TRUE(qsr_quic_parse_initial(packet, sizeof(packet), &initial) == QSR_ERR_UNSUPPORTED);
}

static void test_parse_initial_truncated(void) {
  uint8_t packet[6] = {0xc3, 0x00, 0x00, 0x00, 0x01, 0x08};
  qsr_quic_initial_t initial;
  ASSERT_TRUE(qsr_quic_parse_initial(packet, sizeof(packet), &initial) == QSR_ERR_TRUNCATED);
}

static void test_parse_varint_widths(void) {
  uint64_t value = 0U;
  size_t consumed = 0U;
  const uint8_t v1[] = {0x25};
  ASSERT_TRUE(qsr_quic_parse_varint(v1, sizeof(v1), &value, &consumed) == QSR_OK);
  ASSERT_TRUE(value == 0x25U && consumed == 1U);

  const uint8_t v2[] = {0x7b, 0xbd};
  ASSERT_TRUE(qsr_quic_parse_varint(v2, sizeof(v2), &value, &consumed) == QSR_OK);
  ASSERT_TRUE(value == 0x3bbdU && consumed == 2U);

  const uint8_t v4[] = {0x9d, 0x7f, 0x3e, 0x7d};
  ASSERT_TRUE(qsr_quic_parse_varint(v4, sizeof(v4), &value, &consumed) == QSR_OK);
  ASSERT_TRUE(value == 0x1d7f3e7dU && consumed == 4U);

  const uint8_t v8[] = {0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c};
  ASSERT_TRUE(qsr_quic_parse_varint(v8, sizeof(v8), &value, &consumed) == QSR_OK);
  ASSERT_TRUE(value == 0x2197c5eff14e88cULL && consumed == 8U);

  const uint8_t truncated[] = {0x9d, 0x7f};
  ASSERT_TRUE(qsr_quic_parse_varint(truncated, sizeof(truncated), &value, &consumed) == QSR_ERR_TRUNCATED);

  ASSERT_TRUE(qsr_quic_parse_varint(nullptr, 0U, &value, &consumed) == QSR_ERR_INVALID);
}

void test_quic_initial(void) {
  test_parse_initial_happy_path();
  test_parse_v2_initial_happy_path();
  test_parse_rejects_v2_packet_with_v1_type_bits();
  test_parse_rejects_v1_packet_with_v2_type_bits();
  test_parse_initial_rejects_invalid_fixed_bit();
  test_parse_initial_rejects_non_initial_type();
  test_parse_initial_rejects_short_dcid();
  test_parse_initial_rejects_undersized_payload();
  test_parse_initial_rejects_unknown_version();
  test_parse_initial_truncated();
  test_parse_varint_widths();
}
