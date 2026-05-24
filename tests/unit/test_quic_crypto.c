#include "qsr/quic_crypto.h"
#include "test_main.h"

#include <string.h>

/*
 * Sample DCID used by both RFC 9001 Appendix A (v1) and RFC 9369 Appendix A
 * (v2). Reusing the same DCID across versions is what lets us catch any
 * accidental v1↔v2 cross-contamination of salts or labels: the same input
 * must produce different, version-specific keys.
 */
static const uint8_t sample_dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

static void test_v1_client_keys_match_rfc9001(void) {
  qsr_initial_keys_t keys;
  ASSERT_TRUE(qsr_quic_initial_client_keys(QSR_QUIC_V1, sample_dcid, sizeof(sample_dcid), &keys) == QSR_OK);
  /* RFC 9001 Appendix A.1 sample. */
  static const uint8_t expected_key[16] = {0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
                                           0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d};
  static const uint8_t expected_iv[12] = {0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3,
                                          0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c};
  static const uint8_t expected_hp[16] = {0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
                                          0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2};
  ASSERT_TRUE(memcmp(keys.key, expected_key, sizeof(expected_key)) == 0);
  ASSERT_TRUE(memcmp(keys.iv, expected_iv, sizeof(expected_iv)) == 0);
  ASSERT_TRUE(memcmp(keys.hp, expected_hp, sizeof(expected_hp)) == 0);
}

static void test_v2_client_keys_match_rfc9369(void) {
  qsr_initial_keys_t keys;
  ASSERT_TRUE(qsr_quic_initial_client_keys(QSR_QUIC_V2, sample_dcid, sizeof(sample_dcid), &keys) == QSR_OK);
  /*
   * Expected output for HKDF-Extract(quicv2_salt, sample_dcid) then HKDF-
   * Expand-Label(., "quicv2 key|iv|hp", "", N) per RFC 9369 §5.1 + §5.3.
   * The v1 test above pins our HKDF and label encoding against the
   * RFC 9001 ground truth, so these bytes are deterministically the
   * RFC 9369-correct values by construction — change either the v2 salt
   * or any v2 label and this test trips.
   */
  static const uint8_t expected_key[16] = {0x8b, 0x1a, 0x0b, 0xc1, 0x21, 0x28, 0x42, 0x90,
                                           0xa2, 0x9e, 0x09, 0x71, 0xb5, 0xcd, 0x04, 0x5d};
  static const uint8_t expected_iv[12] = {0x91, 0xf7, 0x3e, 0x23, 0x51, 0xd8,
                                          0xfa, 0x91, 0x66, 0x0e, 0x90, 0x9f};
  static const uint8_t expected_hp[16] = {0x45, 0xb9, 0x5e, 0x15, 0x23, 0x5d, 0x6f, 0x45,
                                          0xa6, 0xb1, 0x9c, 0xbc, 0xb0, 0x29, 0x4b, 0xa9};
  ASSERT_TRUE(memcmp(keys.key, expected_key, sizeof(expected_key)) == 0);
  ASSERT_TRUE(memcmp(keys.iv, expected_iv, sizeof(expected_iv)) == 0);
  ASSERT_TRUE(memcmp(keys.hp, expected_hp, sizeof(expected_hp)) == 0);
}

/*
 * Sanity: identical DCID with v1 vs v2 must yield distinct keys, otherwise
 * we've crossed wires somewhere (typo in salt, label, or version dispatch).
 */
static void test_v1_and_v2_keys_differ_for_same_dcid(void) {
  qsr_initial_keys_t v1_keys;
  qsr_initial_keys_t v2_keys;
  ASSERT_TRUE(qsr_quic_initial_client_keys(QSR_QUIC_V1, sample_dcid, sizeof(sample_dcid), &v1_keys) == QSR_OK);
  ASSERT_TRUE(qsr_quic_initial_client_keys(QSR_QUIC_V2, sample_dcid, sizeof(sample_dcid), &v2_keys) == QSR_OK);
  ASSERT_TRUE(memcmp(v1_keys.key, v2_keys.key, sizeof(v1_keys.key)) != 0);
  ASSERT_TRUE(memcmp(v1_keys.iv, v2_keys.iv, sizeof(v1_keys.iv)) != 0);
  ASSERT_TRUE(memcmp(v1_keys.hp, v2_keys.hp, sizeof(v1_keys.hp)) != 0);
}

static void test_rejects_unknown_version(void) {
  qsr_initial_keys_t keys;
  ASSERT_TRUE(qsr_quic_initial_client_keys(0x0a0a0a0aU, sample_dcid, sizeof(sample_dcid), &keys) ==
              QSR_ERR_UNSUPPORTED);
}

static void test_rejects_invalid_input(void) {
  qsr_initial_keys_t keys;
  ASSERT_TRUE(qsr_quic_initial_client_keys(QSR_QUIC_V1, nullptr, 8, &keys) == QSR_ERR_INVALID);
  ASSERT_TRUE(qsr_quic_initial_client_keys(QSR_QUIC_V1, sample_dcid, 0, &keys) == QSR_ERR_INVALID);
  ASSERT_TRUE(qsr_quic_initial_client_keys(QSR_QUIC_V1, sample_dcid, QSR_MAX_QUIC_CID_LEN + 1U, &keys) ==
              QSR_ERR_INVALID);
  ASSERT_TRUE(qsr_quic_initial_client_keys(QSR_QUIC_V1, sample_dcid, sizeof(sample_dcid), nullptr) == QSR_ERR_INVALID);
}

void test_quic_crypto(void) {
  test_v1_client_keys_match_rfc9001();
  test_v2_client_keys_match_rfc9369();
  test_v1_and_v2_keys_differ_for_same_dcid();
  test_rejects_unknown_version();
  test_rejects_invalid_input();
}
