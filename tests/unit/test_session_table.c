#include "qsr/session_table.h"
#include "test_main.h"

#include <string.h>

static struct sockaddr_storage make_v4(uint32_t addr_be, uint16_t port_be) {
  struct sockaddr_storage ss = {0};
  struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = addr_be;
  sin->sin_port = port_be;
  return ss;
}

static void test_put_get_roundtrip(void) {
  qsr_session_table_t table;
  ASSERT_TRUE(qsr_session_table_init(&table, 4U) == QSR_OK);

  struct sockaddr_storage backend = make_v4(0x0100007fU /* 127.0.0.1 */, 8443U);
  qsr_session_key_t key = qsr_session_tuple_key(&backend, sizeof(struct sockaddr_in));
  ASSERT_TRUE(qsr_session_table_put(&table, &key, &backend, sizeof(struct sockaddr_in), 10) == QSR_OK);
  ASSERT_TRUE(qsr_session_table_get(&table, &key) != nullptr);

  const uint8_t dcid[] = {1, 2, 3, 4};
  const uint8_t scid[] = {5, 6, 7, 8};
  qsr_session_key_t pair = qsr_session_cid_key(dcid, sizeof(dcid), scid, sizeof(scid));
  ASSERT_TRUE(qsr_session_table_put(&table, &pair, &backend, sizeof(struct sockaddr_in), 10) == QSR_OK);
  ASSERT_TRUE(qsr_session_table_get(&table, &pair) != nullptr);

  qsr_session_table_free(&table);
}

static void test_invalid_keys_rejected(void) {
  qsr_session_table_t table;
  ASSERT_TRUE(qsr_session_table_init(&table, 4U) == QSR_OK);
  struct sockaddr_storage backend = make_v4(0x0100007fU, 8443U);
  qsr_session_key_t bad = {0};
  bad.has_cids = true;
  bad.dcid_len = QSR_MAX_QUIC_CID_LEN + 1U;
  ASSERT_TRUE(qsr_session_table_get(&table, &bad) == nullptr);
  ASSERT_TRUE(qsr_session_table_put(&table, &bad, &backend, sizeof(struct sockaddr_in), 0) == QSR_ERR_INVALID);
  qsr_session_table_free(&table);
}

/*
 * Regression test for the original delete-by-zero bug: deleting an entry must
 * not orphan keys whose probe chain passed through that slot. We force a
 * collision by inserting two CIDs that hash to adjacent buckets in a tiny
 * table, expire the first one, and confirm the second is still found.
 */
static void test_expire_preserves_probe_chain(void) {
  qsr_session_table_t table;
  ASSERT_TRUE(qsr_session_table_init(&table, 8U) == QSR_OK);
  struct sockaddr_storage backend = make_v4(0x0100007fU, 8443U);

  /*
   * Insert 4 distinct CIDs. With a capacity-8 table this guarantees several
   * probes and at least one collision chain. After expiring two of them and
   * keeping the other two with a recent timestamp, all four lookups must
   * behave correctly (hits and a miss).
   */
  qsr_session_key_t keep_a = qsr_session_single_cid_key(
      (const uint8_t[]){0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}, 8);
  qsr_session_key_t keep_b = qsr_session_single_cid_key(
      (const uint8_t[]){0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB}, 8);
  qsr_session_key_t drop_a = qsr_session_single_cid_key(
      (const uint8_t[]){0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC}, 8);
  qsr_session_key_t drop_b = qsr_session_single_cid_key(
      (const uint8_t[]){0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD}, 8);

  ASSERT_TRUE(qsr_session_table_put(&table, &keep_a, &backend, sizeof(struct sockaddr_in), 100) == QSR_OK);
  ASSERT_TRUE(qsr_session_table_put(&table, &drop_a, &backend, sizeof(struct sockaddr_in), 10) == QSR_OK);
  ASSERT_TRUE(qsr_session_table_put(&table, &keep_b, &backend, sizeof(struct sockaddr_in), 100) == QSR_OK);
  ASSERT_TRUE(qsr_session_table_put(&table, &drop_b, &backend, sizeof(struct sockaddr_in), 10) == QSR_OK);

  /* Expire entries last seen >= 60 seconds ago at now=100. drop_a and drop_b go. */
  const size_t expired = qsr_session_table_expire(&table, 100, 60);
  ASSERT_TRUE(expired == 2U);

  ASSERT_TRUE(qsr_session_table_get(&table, &keep_a) != nullptr);
  ASSERT_TRUE(qsr_session_table_get(&table, &keep_b) != nullptr);
  ASSERT_TRUE(qsr_session_table_get(&table, &drop_a) == nullptr);
  ASSERT_TRUE(qsr_session_table_get(&table, &drop_b) == nullptr);

  qsr_session_table_free(&table);
}

/*
 * Once the table is at capacity, qsr_session_table_put must evict the oldest
 * entry by last_seen rather than just returning QSR_ERR_FULL. Otherwise an
 * attacker can lock out legitimate clients by spamming Initials.
 */
static void test_lru_eviction_when_full(void) {
  qsr_session_table_t table;
  ASSERT_TRUE(qsr_session_table_init(&table, 4U) == QSR_OK);
  struct sockaddr_storage backend = make_v4(0x0100007fU, 8443U);

  qsr_session_key_t k[5];
  for (size_t i = 0; i < 5; i++) {
    const uint8_t cid[8] = {(uint8_t)(0x10 + i), 0, 0, 0, 0, 0, 0, 0};
    k[i] = qsr_session_single_cid_key(cid, 8);
  }
  ASSERT_TRUE(qsr_session_table_put(&table, &k[0], &backend, sizeof(struct sockaddr_in), 1) == QSR_OK);
  ASSERT_TRUE(qsr_session_table_put(&table, &k[1], &backend, sizeof(struct sockaddr_in), 2) == QSR_OK);
  ASSERT_TRUE(qsr_session_table_put(&table, &k[2], &backend, sizeof(struct sockaddr_in), 3) == QSR_OK);
  ASSERT_TRUE(qsr_session_table_put(&table, &k[3], &backend, sizeof(struct sockaddr_in), 4) == QSR_OK);

  /* Table full; inserting another should evict k[0] (oldest) and succeed. */
  ASSERT_TRUE(qsr_session_table_put(&table, &k[4], &backend, sizeof(struct sockaddr_in), 5) == QSR_OK);
  ASSERT_TRUE(qsr_session_table_get(&table, &k[0]) == nullptr);
  ASSERT_TRUE(qsr_session_table_get(&table, &k[4]) != nullptr);

  qsr_session_table_free(&table);
}

static bool predicate_evict_all(const qsr_session_t *s, void *userdata) {
  (void)s;
  (void)userdata;
  return true;
}

static bool predicate_evict_none(const qsr_session_t *s, void *userdata) {
  (void)s;
  (void)userdata;
  return false;
}

typedef struct evict_match_addr {
  struct sockaddr_storage target;
  socklen_t target_len;
} evict_match_addr_t;

static bool predicate_evict_matching_backend(const qsr_session_t *s, void *userdata) {
  const evict_match_addr_t *match = userdata;
  return s->backend_addr_len == match->target_len &&
         memcmp(&s->backend_addr, &match->target, match->target_len) == 0;
}

static void test_evict_if_returns_zero_when_empty(void) {
  qsr_session_table_t table;
  ASSERT_TRUE(qsr_session_table_init(&table, 4U) == QSR_OK);
  ASSERT_TRUE(qsr_session_table_evict_if(&table, predicate_evict_all, nullptr) == 0U);
  qsr_session_table_free(&table);
}

static void test_evict_if_all_clears_table(void) {
  qsr_session_table_t table;
  ASSERT_TRUE(qsr_session_table_init(&table, 8U) == QSR_OK);
  struct sockaddr_storage backend = make_v4(0x0100007fU, 8443U);
  for (size_t i = 0; i < 5; i++) {
    const uint8_t cid[8] = {(uint8_t)(0x40 + i), 0, 0, 0, 0, 0, 0, 0};
    qsr_session_key_t k = qsr_session_single_cid_key(cid, 8);
    ASSERT_TRUE(qsr_session_table_put(&table, &k, &backend, sizeof(struct sockaddr_in), 1) == QSR_OK);
  }
  ASSERT_TRUE(qsr_session_table_evict_if(&table, predicate_evict_all, nullptr) == 5U);
  ASSERT_TRUE(table.count == 0U);
  qsr_session_table_free(&table);
}

static void test_evict_if_none_keeps_table(void) {
  qsr_session_table_t table;
  ASSERT_TRUE(qsr_session_table_init(&table, 8U) == QSR_OK);
  struct sockaddr_storage backend = make_v4(0x0100007fU, 8443U);
  for (size_t i = 0; i < 3; i++) {
    const uint8_t cid[8] = {(uint8_t)(0x50 + i), 0, 0, 0, 0, 0, 0, 0};
    qsr_session_key_t k = qsr_session_single_cid_key(cid, 8);
    ASSERT_TRUE(qsr_session_table_put(&table, &k, &backend, sizeof(struct sockaddr_in), 1) == QSR_OK);
  }
  ASSERT_TRUE(qsr_session_table_evict_if(&table, predicate_evict_none, nullptr) == 0U);
  ASSERT_TRUE(table.count == 3U);
  qsr_session_table_free(&table);
}

/*
 * Selective eviction (the hot-reload case): evict only sessions whose backend
 * matches a specific address; sessions to other backends must survive AND
 * remain looked-up-able afterward (probe chain integrity check).
 */
static void test_evict_if_selective_preserves_others(void) {
  qsr_session_table_t table;
  ASSERT_TRUE(qsr_session_table_init(&table, 16U) == QSR_OK);
  struct sockaddr_storage backend_doomed = make_v4(0x0a00007fU /* 127.0.0.10 */, 8443U);
  struct sockaddr_storage backend_kept = make_v4(0x0b00007fU /* 127.0.0.11 */, 8443U);

  qsr_session_key_t doomed_keys[3];
  qsr_session_key_t kept_keys[3];
  for (size_t i = 0; i < 3; i++) {
    const uint8_t dc[8] = {(uint8_t)(0x60 + i), 0, 0, 0, 0, 0, 0, 0};
    const uint8_t kc[8] = {(uint8_t)(0x70 + i), 0, 0, 0, 0, 0, 0, 0};
    doomed_keys[i] = qsr_session_single_cid_key(dc, 8);
    kept_keys[i] = qsr_session_single_cid_key(kc, 8);
    ASSERT_TRUE(qsr_session_table_put(&table, &doomed_keys[i], &backend_doomed, sizeof(struct sockaddr_in), 1) ==
                QSR_OK);
    ASSERT_TRUE(qsr_session_table_put(&table, &kept_keys[i], &backend_kept, sizeof(struct sockaddr_in), 1) == QSR_OK);
  }

  evict_match_addr_t match = {.target = backend_doomed, .target_len = sizeof(struct sockaddr_in)};
  ASSERT_TRUE(qsr_session_table_evict_if(&table, predicate_evict_matching_backend, &match) == 3U);
  ASSERT_TRUE(table.count == 3U);
  for (size_t i = 0; i < 3; i++) {
    ASSERT_TRUE(qsr_session_table_get(&table, &doomed_keys[i]) == nullptr);
    ASSERT_TRUE(qsr_session_table_get(&table, &kept_keys[i]) != nullptr);
  }
  qsr_session_table_free(&table);
}

/*
 * Defends short-header CID lookup from the false-match amplification described
 * in common.h. A single-CID alias shorter than QSR_MIN_LEARNED_CID_LEN must
 * not even reach the table — the constructor returns an invalid key so put/get
 * fail with QSR_ERR_INVALID instead of installing the short alias.
 */
static void test_short_cid_alias_rejected(void) {
  qsr_session_table_t table;
  ASSERT_TRUE(qsr_session_table_init(&table, 4U) == QSR_OK);
  struct sockaddr_storage backend = make_v4(0x0100007fU, 8443U);

  /* One byte below the floor (7) — should be rejected. */
  const uint8_t too_short[QSR_MIN_LEARNED_CID_LEN - 1U] = {0};
  qsr_session_key_t bad = qsr_session_single_cid_key(too_short, sizeof(too_short));
  ASSERT_TRUE(qsr_session_table_put(&table, &bad, &backend, sizeof(struct sockaddr_in), 1) == QSR_ERR_INVALID);
  ASSERT_TRUE(qsr_session_table_get(&table, &bad) == nullptr);

  /* Exactly at the floor — accepted. */
  const uint8_t ok_len[QSR_MIN_LEARNED_CID_LEN] = {0};
  qsr_session_key_t ok = qsr_session_single_cid_key(ok_len, sizeof(ok_len));
  ASSERT_TRUE(qsr_session_table_put(&table, &ok, &backend, sizeof(struct sockaddr_in), 1) == QSR_OK);

  /*
   * Pair-CID keys (qsr_session_cid_key with two CIDs) are NOT subject to the
   * min-length floor — they're matched by exact key equality, so the false-
   * match iteration attack doesn't apply. A 4+4 pair must still work for
   * rebound-Initial recovery.
   */
  const uint8_t dc[4] = {0x11, 0x22, 0x33, 0x44};
  const uint8_t sc[4] = {0x55, 0x66, 0x77, 0x88};
  qsr_session_key_t pair = qsr_session_cid_key(dc, sizeof(dc), sc, sizeof(sc));
  ASSERT_TRUE(qsr_session_table_put(&table, &pair, &backend, sizeof(struct sockaddr_in), 1) == QSR_OK);

  qsr_session_table_free(&table);
}

void test_session_table(void) {
  test_put_get_roundtrip();
  test_invalid_keys_rejected();
  test_expire_preserves_probe_chain();
  test_lru_eviction_when_full();
  test_evict_if_returns_zero_when_empty();
  test_evict_if_all_clears_table();
  test_evict_if_none_keeps_table();
  test_evict_if_selective_preserves_others();
  test_short_cid_alias_rejected();
}
