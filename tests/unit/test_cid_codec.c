#include "qsr/cid_codec.h"
#include "test_main.h"

#include <string.h>

static const char TEST_HEX_KEY[] = "00112233445566778899aabbccddeeff";

static void test_init_from_hex_accepts_valid_key(void) {
  qsr_cid_codec_t codec;
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&codec, TEST_HEX_KEY) == QSR_OK);
  ASSERT_TRUE(codec.enabled);
  ASSERT_TRUE(codec.key[0] == 0x00U && codec.key[15] == 0xffU);
}

static void test_init_from_hex_rejects_bad_length(void) {
  qsr_cid_codec_t codec;
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&codec, "") == QSR_ERR_INVALID);
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&codec, "0011223344") == QSR_ERR_INVALID);
  ASSERT_TRUE(!codec.enabled);
}

static void test_init_from_hex_rejects_non_hex_chars(void) {
  qsr_cid_codec_t codec;
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&codec, "zz112233445566778899aabbccddeeff") == QSR_ERR_INVALID);
  ASSERT_TRUE(!codec.enabled);
}

static void test_encode_decode_roundtrip(void) {
  qsr_cid_codec_t codec;
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&codec, TEST_HEX_KEY) == QSR_OK);
  uint8_t nonce[QSR_CID_NONCE_LEN] = {1, 2, 3, 4, 5, 6, 7};
  uint8_t cid[QSR_CID_ENCODED_LEN] = {0};
  ASSERT_TRUE(qsr_cid_codec_encode(&codec, 42U, nonce, cid) == QSR_OK);
  /* Version byte and nonce stay in cleartext. */
  ASSERT_TRUE(cid[0] == QSR_CID_ENCODED_VERSION);
  ASSERT_TRUE(memcmp(&cid[1], nonce, QSR_CID_NONCE_LEN) == 0);
  uint8_t server_id = 0U;
  ASSERT_TRUE(qsr_cid_codec_decode(&codec, cid, sizeof(cid), &server_id) == QSR_OK);
  ASSERT_TRUE(server_id == 42U);
}

/*
 * The migration-routing property: any CID generated with a given server_id
 * and the shared key decodes back to that server_id, regardless of nonce.
 * This is the load-bearing guarantee that lets the router follow an active
 * QUIC migration to a freshly-issued CID it has never observed.
 */
static void test_different_nonces_yield_same_server_id(void) {
  qsr_cid_codec_t codec;
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&codec, TEST_HEX_KEY) == QSR_OK);
  uint8_t nonce_a[QSR_CID_NONCE_LEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
  uint8_t nonce_b[QSR_CID_NONCE_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
  uint8_t cid_a[QSR_CID_ENCODED_LEN] = {0};
  uint8_t cid_b[QSR_CID_ENCODED_LEN] = {0};
  ASSERT_TRUE(qsr_cid_codec_encode(&codec, 17U, nonce_a, cid_a) == QSR_OK);
  ASSERT_TRUE(qsr_cid_codec_encode(&codec, 17U, nonce_b, cid_b) == QSR_OK);
  /* Different nonces must produce different ciphertexts (no fixed-IV reuse). */
  ASSERT_TRUE(memcmp(&cid_a[1U + QSR_CID_NONCE_LEN], &cid_b[1U + QSR_CID_NONCE_LEN], QSR_CID_PAYLOAD_LEN) != 0);
  uint8_t sid_a = 0U;
  uint8_t sid_b = 0U;
  ASSERT_TRUE(qsr_cid_codec_decode(&codec, cid_a, sizeof(cid_a), &sid_a) == QSR_OK);
  ASSERT_TRUE(qsr_cid_codec_decode(&codec, cid_b, sizeof(cid_b), &sid_b) == QSR_OK);
  ASSERT_TRUE(sid_a == 17U && sid_b == 17U);
}

static void test_encode_rejects_zero_server_id(void) {
  qsr_cid_codec_t codec;
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&codec, TEST_HEX_KEY) == QSR_OK);
  uint8_t nonce[QSR_CID_NONCE_LEN] = {0};
  uint8_t cid[QSR_CID_ENCODED_LEN] = {0};
  ASSERT_TRUE(qsr_cid_codec_encode(&codec, 0U, nonce, cid) == QSR_ERR_INVALID);
}

static void test_decode_rejects_wrong_length(void) {
  qsr_cid_codec_t codec;
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&codec, TEST_HEX_KEY) == QSR_OK);
  uint8_t cid[QSR_CID_ENCODED_LEN] = {QSR_CID_ENCODED_VERSION};
  uint8_t sid = 0U;
  ASSERT_TRUE(qsr_cid_codec_decode(&codec, cid, 8U, &sid) == QSR_ERR_INVALID);
  ASSERT_TRUE(qsr_cid_codec_decode(&codec, cid, QSR_CID_ENCODED_LEN + 1U, &sid) == QSR_ERR_INVALID);
}

static void test_decode_rejects_wrong_version_byte(void) {
  qsr_cid_codec_t codec;
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&codec, TEST_HEX_KEY) == QSR_OK);
  uint8_t nonce[QSR_CID_NONCE_LEN] = {0};
  uint8_t cid[QSR_CID_ENCODED_LEN] = {0};
  ASSERT_TRUE(qsr_cid_codec_encode(&codec, 1U, nonce, cid) == QSR_OK);
  cid[0] ^= 0x01U;
  uint8_t sid = 0U;
  ASSERT_TRUE(qsr_cid_codec_decode(&codec, cid, sizeof(cid), &sid) == QSR_ERR_INVALID);
}

/*
 * Magic check: corrupt one byte of the encrypted payload. The magic now
 * mismatches with overwhelming probability and decode must fail. Without
 * the magic check, the corrupted CID would silently re-route to a random
 * server_id.
 */
static void test_decode_rejects_corrupt_ciphertext(void) {
  qsr_cid_codec_t codec;
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&codec, TEST_HEX_KEY) == QSR_OK);
  uint8_t nonce[QSR_CID_NONCE_LEN] = {0};
  uint8_t cid[QSR_CID_ENCODED_LEN] = {0};
  ASSERT_TRUE(qsr_cid_codec_encode(&codec, 99U, nonce, cid) == QSR_OK);
  cid[10] ^= 0x80U;
  uint8_t sid = 0U;
  ASSERT_TRUE(qsr_cid_codec_decode(&codec, cid, sizeof(cid), &sid) == QSR_ERR_INVALID);
}

/*
 * A CID generated with key A must not decode under key B. Catches a
 * configuration error where the router and the backend are out of sync.
 */
static void test_decode_rejects_wrong_key(void) {
  qsr_cid_codec_t backend;
  qsr_cid_codec_t router;
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&backend, TEST_HEX_KEY) == QSR_OK);
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&router, "ffeeddccbbaa99887766554433221100") == QSR_OK);
  uint8_t nonce[QSR_CID_NONCE_LEN] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x01};
  uint8_t cid[QSR_CID_ENCODED_LEN] = {0};
  ASSERT_TRUE(qsr_cid_codec_encode(&backend, 5U, nonce, cid) == QSR_OK);
  uint8_t sid = 0U;
  ASSERT_TRUE(qsr_cid_codec_decode(&router, cid, sizeof(cid), &sid) == QSR_ERR_INVALID);
}

/*
 * Random 16-byte buffers (whose first byte happens to match the version)
 * should not decode. With 7-byte magic the false-positive rate is ~2^-56;
 * a few hundred trials is a sanity check, not a statistical guarantee.
 */
static void test_decode_rejects_random_cids(void) {
  qsr_cid_codec_t codec;
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&codec, TEST_HEX_KEY) == QSR_OK);
  uint8_t cid[QSR_CID_ENCODED_LEN];
  cid[0] = QSR_CID_ENCODED_VERSION;
  for (unsigned trial = 0U; trial < 500U; trial++) {
    for (size_t i = 1U; i < QSR_CID_ENCODED_LEN; i++) {
      cid[i] = (uint8_t)(((size_t)trial * 31U + i * 7U) & 0xffU);
    }
    uint8_t sid = 0U;
    ASSERT_TRUE(qsr_cid_codec_decode(&codec, cid, sizeof(cid), &sid) == QSR_ERR_INVALID);
  }
}

static void test_disabled_codec_rejects_everything(void) {
  qsr_cid_codec_t codec = {0};
  uint8_t nonce[QSR_CID_NONCE_LEN] = {0};
  uint8_t cid[QSR_CID_ENCODED_LEN] = {0};
  uint8_t sid = 0U;
  ASSERT_TRUE(qsr_cid_codec_encode(&codec, 1U, nonce, cid) == QSR_ERR_INVALID);
  ASSERT_TRUE(qsr_cid_codec_decode(&codec, cid, sizeof(cid), &sid) == QSR_ERR_INVALID);
}

void test_cid_codec(void);

void test_cid_codec(void) {
  test_init_from_hex_accepts_valid_key();
  test_init_from_hex_rejects_bad_length();
  test_init_from_hex_rejects_non_hex_chars();
  test_encode_decode_roundtrip();
  test_different_nonces_yield_same_server_id();
  test_encode_rejects_zero_server_id();
  test_decode_rejects_wrong_length();
  test_decode_rejects_wrong_version_byte();
  test_decode_rejects_corrupt_ciphertext();
  test_decode_rejects_wrong_key();
  test_decode_rejects_random_cids();
  test_disabled_codec_rejects_everything();
}
