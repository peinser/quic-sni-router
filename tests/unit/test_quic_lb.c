#include "qsr/quic_lb.h"
#include "qsr/route_table.h"
#include "test_main.h"

#include <openssl/crypto.h>
#include <string.h>

static size_t unhex(const char *hex, uint8_t *out, size_t capacity) {
  size_t len = 0;
  ASSERT_TRUE(OPENSSL_hexstr2buf_ex(out, capacity, &len, hex, '\0') == 1);
  return len;
}

void test_quic_lb(void);

void test_quic_lb(void) {
  /* Draft -21 Appendix B encrypted vectors, also used by QUICHE's decoder
   * tests. The last draft row says config 3 but its wire octet 0x12 means 0;
   * use the actual wire bits, as QUICHE does. */
  const struct {
    const char *cid;
    const char *sid;
    uint8_t nonce_len;
  } vectors[] = {
      {"0720b1d07b359d3c", "ed793a", 4},
      {"2fcc381bc74cb4fbad2823a3d1f8fed2", "ed793a51d49b8f5fab65", 5},
      {"504dd2d05a7b0de9b2b9907afb5ecf8cc3", "ed793a51d49b8f5f", 8},
      {"125779c9cc86beb3a3a4a3ca96fce4bfe0cdbc", "ed793a51d49b8f5fab", 9},
  };
  uint8_t key[16];
  ASSERT_TRUE(unhex("8f95f09245765f80256934e50c66207f", key, sizeof(key)) == sizeof(key));
  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
    uint8_t cid[20] = {0};
    qsr_quic_lb_server_id_t expected = {0};
    const size_t cid_len = unhex(vectors[i].cid, cid, sizeof(cid));
    expected.len = (uint8_t)unhex(vectors[i].sid, expected.bytes, sizeof(expected.bytes));
    qsr_quic_lb_t lb = {0};
    const uint8_t rotation = cid[0] >> 5U;
    ASSERT_TRUE(qsr_quic_lb_config_init(&lb, rotation, expected.len, vectors[i].nonce_len, key) == QSR_OK);
    qsr_quic_lb_server_id_t decoded;
    uint8_t selected = 7;
    ASSERT_TRUE(qsr_quic_lb_decode(&lb, cid, cid_len, &selected, &decoded) == QSR_OK);
    ASSERT_TRUE(selected == rotation && decoded.len == expected.len);
    ASSERT_TRUE(memcmp(decoded.bytes, expected.bytes, expected.len) == 0);
    /* Low five bits need not encode length; arbitrary suffix bytes are legal. */
    cid[0] ^= 0x1f;
    ASSERT_TRUE(qsr_quic_lb_decode(&lb, cid, sizeof(cid), &selected, &decoded) == QSR_OK);
    ASSERT_TRUE(memcmp(decoded.bytes, expected.bytes, expected.len) == 0);
    for (size_t n = 0; n < cid_len; n++) {
      ASSERT_TRUE(qsr_quic_lb_decode(&lb, cid, n, &selected, &decoded) != QSR_OK);
    }
  }

  /* Section 5.4.2.4 uses another key: the cached AES context must rekey. */
  {
    qsr_quic_lb_t example = {0};
    uint8_t example_key[16];
    uint8_t example_cid[8];
    ASSERT_TRUE(unhex("fdf726a9893ec05c0632d3956680baf0", example_key, sizeof(example_key)) == 16);
    ASSERT_TRUE(unhex("0767947d29be054a", example_cid, sizeof(example_cid)) == 8);
    ASSERT_TRUE(qsr_quic_lb_config_init(&example, 0, 3, 4, example_key) == QSR_OK);
    qsr_quic_lb_server_id_t answer;
    uint8_t selected;
    ASSERT_TRUE(qsr_quic_lb_decode(&example, example_cid, sizeof(example_cid), &selected, &answer) == QSR_OK);
    const uint8_t expected[] = {0x31, 0x44, 0x1a};
    ASSERT_TRUE(answer.len == 3 && memcmp(answer.bytes, expected, sizeof(expected)) == 0);
  }

  /* Unencrypted Appendix B.1's valid row. Its second row contains malformed
   * odd-length hex; also cover a canonical QUICHE unencrypted vector. */
  qsr_quic_lb_t lb = {0};
  ASSERT_TRUE(qsr_quic_lb_config_init(&lb, 0, 3, 4, nullptr) == QSR_OK);
  ASSERT_TRUE(qsr_quic_lb_config_init(&lb, 1, 8, 5, nullptr) == QSR_OK);
  uint8_t cid[20];
  size_t len = unhex("07c4605e4504cc4f", cid, sizeof(cid));
  uint8_t rotation;
  qsr_quic_lb_server_id_t decoded;
  ASSERT_TRUE(qsr_quic_lb_decode(&lb, cid, len, &rotation, &decoded) == QSR_OK);
  const uint8_t sid[] = {0xc4, 0x60, 0x5e};
  ASSERT_TRUE(rotation == 0 && decoded.len == sizeof(sid) && memcmp(decoded.bytes, sid, sizeof(sid)) == 0);
  len = unhex("2ded793a51d49b8f5fee15da27c4", cid, sizeof(cid));
  ASSERT_TRUE(qsr_quic_lb_decode(&lb, cid, len, &rotation, &decoded) == QSR_OK && rotation == 1 && decoded.len == 8);
  ASSERT_TRUE(memcmp(decoded.bytes, cid + 1, 8) == 0);
  cid[0] = 0xe0;
  ASSERT_TRUE(qsr_quic_lb_decode(&lb, cid, len, &rotation, &decoded) == QSR_ERR_NOT_FOUND);
  cid[0] = 0x40;
  ASSERT_TRUE(qsr_quic_lb_decode(&lb, cid, len, &rotation, &decoded) == QSR_ERR_NOT_FOUND);
  ASSERT_TRUE(qsr_quic_lb_config_init(&lb, 0, 3, 4, key) == QSR_ERR_INVALID);
  ASSERT_TRUE(qsr_quic_lb_config_init(&lb, 7, 3, 4, key) == QSR_ERR_INVALID);
  ASSERT_TRUE(qsr_quic_lb_config_init(&lb, 2, 0, 4, key) == QSR_ERR_INVALID);
  ASSERT_TRUE(qsr_quic_lb_config_init(&lb, 2, 1, 3, key) == QSR_ERR_INVALID);
  ASSERT_TRUE(qsr_quic_lb_config_init(&lb, 2, 15, 5, key) == QSR_ERR_INVALID);
  ASSERT_TRUE(qsr_quic_lb_config_init(&lb, 6, 15, 4, nullptr) == QSR_OK);
  memset(cid, 0, sizeof(cid));
  cid[0] = 0xc0;
  ASSERT_TRUE(qsr_quic_lb_decode(&lb, cid, sizeof(cid), &rotation, &decoded) == QSR_OK && decoded.len == 15);

  qsr_route_table_t table;
  qsr_route_table_init(&table);
  ASSERT_TRUE(qsr_route_table_add(&table, "one.test", "127.0.0.1", 8443, 0) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_add(&table, "two.test", "127.0.0.1", 8444, 0) == QSR_OK);
  /* All-zero IDs and the same ID in separate configurations are legal. */
  ASSERT_TRUE(qsr_route_table_set_quic_lb_id(&table, 0, 6, &decoded) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_set_quic_lb_id(&table, 1, 5, &decoded) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_set_quic_lb_id(&table, 1, 6, &decoded) == QSR_ERR_INVALID);
  ASSERT_TRUE(qsr_route_table_lookup_quic_lb(&table, 6, &decoded) == &table.routes[0]);
  ASSERT_TRUE(qsr_route_table_lookup_quic_lb(&table, 5, &decoded) == &table.routes[1]);
  decoded.bytes[14] = 1;
  ASSERT_TRUE(qsr_route_table_lookup_quic_lb(&table, 6, &decoded) == nullptr);
}
