#include "qsr/flow_table.h"
#include "qsr/runtime.h"
#include "qsr/session_table.h"
#include "test_main.h"

#include <string.h>
#include <unistd.h>

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
  qsr_session_key_t keep_a =
      qsr_session_single_cid_key((const uint8_t[]){0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}, 8);
  qsr_session_key_t keep_b =
      qsr_session_single_cid_key((const uint8_t[]){0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB}, 8);
  qsr_session_key_t drop_a =
      qsr_session_single_cid_key((const uint8_t[]){0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC}, 8);
  qsr_session_key_t drop_b =
      qsr_session_single_cid_key((const uint8_t[]){0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD}, 8);

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

static void test_incremental_expire_respects_budget(void) {
  qsr_session_table_t table;
  ASSERT_TRUE(qsr_session_table_init(&table, 4U) == QSR_OK);
  struct sockaddr_storage backend = make_v4(0x0100007fU, 8443U);

  qsr_session_key_t old_keys[4];
  for (size_t i = 0; i < 4; i++) {
    const uint8_t cid[8] = {(uint8_t)(0x20 + i), 0, 0, 0, 0, 0, 0, 0};
    old_keys[i] = qsr_session_single_cid_key(cid, 8);
    ASSERT_TRUE(qsr_session_table_put(&table, &old_keys[i], &backend, sizeof(struct sockaddr_in), 1) == QSR_OK);
  }

  const size_t first = qsr_session_table_expire_incremental(&table, 100, 60, 2U, nullptr, nullptr);
  ASSERT_TRUE(first <= 2U);
  ASSERT_TRUE(table.count >= 2U);
  size_t total = first;
  for (size_t i = 0; i < 8U && table.count > 0U; i++) {
    total += qsr_session_table_expire_incremental(&table, 100, 60, 2U, nullptr, nullptr);
  }
  ASSERT_TRUE(total == 4U);
  ASSERT_TRUE(table.count == 0U);

  qsr_session_table_free(&table);
}

static void test_cid_length_mask_tracks_inserted_lengths(void) {
  qsr_session_table_t table;
  ASSERT_TRUE(qsr_session_table_init(&table, 8U) == QSR_OK);
  struct sockaddr_storage backend = make_v4(0x0100007fU, 8443U);

  const uint8_t cid8[8] = {0x80, 0, 0, 0, 0, 0, 0, 0};
  const uint8_t cid12[12] = {0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  qsr_session_key_t k8 = qsr_session_single_cid_key(cid8, sizeof(cid8));
  qsr_session_key_t k12 = qsr_session_single_cid_key(cid12, sizeof(cid12));
  ASSERT_TRUE(qsr_session_table_put(&table, &k8, &backend, sizeof(struct sockaddr_in), 1) == QSR_OK);
  ASSERT_TRUE(qsr_session_table_put(&table, &k12, &backend, sizeof(struct sockaddr_in), 1) == QSR_OK);

  const uint32_t mask = qsr_session_table_cid_len_mask(&table);
  ASSERT_TRUE((mask & (1U << 8U)) != 0U);
  ASSERT_TRUE((mask & (1U << 12U)) != 0U);
  ASSERT_TRUE((mask & (1U << 9U)) == 0U);

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
  return s->backend_addr_len == match->target_len && memcmp(&s->backend_addr, &match->target, match->target_len) == 0;
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

/* keep_fn used below: keep exactly the sessions whose key matches *userdata. */
static bool keep_matching_key(const qsr_session_t *session, void *userdata) {
  const qsr_session_key_t *kept = userdata;
  return session->key.has_cids == kept->has_cids && session->key.dcid_len == kept->dcid_len &&
         memcmp(session->key.dcid, kept->dcid, kept->dcid_len) == 0;
}

/*
 * One expire_incremental call caps scans at capacity, and a deletion consumes
 * a scan without advancing the cursor, so a single call is not guaranteed to
 * visit every slot (slot placement is SipHash-randomized per process). Sweep
 * repeatedly, the way the production loop does, so assertions do not depend
 * on hash luck.
 */
static size_t sweep_all(qsr_session_table_t *table, time_t now, time_t idle_timeout_seconds, qsr_session_keep_fn keep,
                        void *userdata) {
  size_t expired = 0U;
  for (size_t i = 0U; i < 8U; i++) {
    expired += qsr_session_table_expire_incremental(table, now, idle_timeout_seconds, table->capacity, keep, userdata);
  }
  return expired;
}

/*
 * Effect test for the keep-alive sweep: an idle-expired session for which the
 * keep callback returns true must survive with a refreshed last_seen, while
 * every other expired session is deleted.
 */
static void test_incremental_expire_keep_callback(void) {
  qsr_session_table_t table;
  ASSERT_TRUE(qsr_session_table_init(&table, 8U) == QSR_OK);
  struct sockaddr_storage backend = make_v4(0x0100007fU, 8443U);

  const uint8_t kept_cid[8] = {0xAA, 0, 0, 0, 0, 0, 0, 0};
  const uint8_t dropped_cid[8] = {0xBB, 0, 0, 0, 0, 0, 0, 0};
  qsr_session_key_t kept_key = qsr_session_single_cid_key(kept_cid, sizeof(kept_cid));
  qsr_session_key_t dropped_key = qsr_session_single_cid_key(dropped_cid, sizeof(dropped_cid));
  ASSERT_TRUE(qsr_session_table_put(&table, &kept_key, &backend, sizeof(struct sockaddr_in), 1) == QSR_OK);
  ASSERT_TRUE(qsr_session_table_put(&table, &dropped_key, &backend, sizeof(struct sockaddr_in), 1) == QSR_OK);

  /* Both are idle-expired at now=100 with a 60s timeout. */
  const size_t expired = sweep_all(&table, 100, 60, keep_matching_key, &kept_key);
  ASSERT_TRUE(expired == 1U);
  const qsr_session_t *kept = qsr_session_table_get(&table, &kept_key);
  ASSERT_TRUE(kept != nullptr);
  ASSERT_TRUE(kept->last_seen == 100);
  ASSERT_TRUE(qsr_session_table_get(&table, &dropped_key) == nullptr);

  /* Without the callback the kept session expires once truly idle again. */
  ASSERT_TRUE(sweep_all(&table, 200, 60, nullptr, nullptr) == 1U);
  ASSERT_TRUE(qsr_session_table_get(&table, &kept_key) == nullptr);

  qsr_session_table_free(&table);
}

/*
 * Effect test for the cid_len_mask rebuild: after the sessions carrying an
 * unusual CID length expire, a full incremental sweep cycle must retire that
 * length's bit so short-header scans stop probing it, while lengths still in
 * use keep their bit.
 */
static void test_cid_length_mask_retires_stale_bits(void) {
  qsr_session_table_t table;
  ASSERT_TRUE(qsr_session_table_init(&table, 8U) == QSR_OK);
  struct sockaddr_storage backend = make_v4(0x0100007fU, 8443U);

  const uint8_t cid8[8] = {0xC0, 0, 0, 0, 0, 0, 0, 0};
  const uint8_t cid20[20] = {0xC1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  qsr_session_key_t k8 = qsr_session_single_cid_key(cid8, sizeof(cid8));
  qsr_session_key_t k20 = qsr_session_single_cid_key(cid20, sizeof(cid20));
  ASSERT_TRUE(qsr_session_table_put(&table, &k20, &backend, sizeof(struct sockaddr_in), 1) == QSR_OK);
  ASSERT_TRUE((qsr_session_table_cid_len_mask(&table) & (1U << 20U)) != 0U);

  /* Expire the 20-byte session; keep the 8-byte one alive across sweeps.
   * sweep_all runs several full cursor cycles, guaranteeing at least one
   * pending-mask swap after the deletion wherever the cursor sat. */
  ASSERT_TRUE(qsr_session_table_put(&table, &k8, &backend, sizeof(struct sockaddr_in), 90) == QSR_OK);
  ASSERT_TRUE(sweep_all(&table, 100, 60, nullptr, nullptr) == 1U);

  const uint32_t mask = qsr_session_table_cid_len_mask(&table);
  ASSERT_TRUE((mask & (1U << 20U)) == 0U);
  ASSERT_TRUE((mask & (1U << 8U)) != 0U);
  ASSERT_TRUE(qsr_session_table_get(&table, &k8) != nullptr);

  qsr_session_table_free(&table);
}

/*
 * End-to-end effect test for the flow-keepalive fix, using the real runtime
 * predicate: a CID alias owned by a live flow survives the sweep while the
 * flow carries traffic, and expires one idle period after the flow dies.
 * Before the fix every alias of a long-lived connection expired after
 * idleTimeout even under continuous traffic.
 */
static void test_flow_owned_alias_survives_active_flow(void) {
  qsr_session_table_t sessions;
  qsr_flow_table_t flows;
  ASSERT_TRUE(qsr_session_table_init(&sessions, 8U) == QSR_OK);
  ASSERT_TRUE(qsr_flow_table_init(&flows, 4U) == QSR_OK);

  struct sockaddr_storage client = make_v4(0x0100007fU, 50000U);
  struct sockaddr_storage backend = make_v4(0x0200007fU, 8443U);
  const int fd = dup(0);
  ASSERT_TRUE(fd >= 0);
  qsr_flow_t *flow = qsr_flow_table_put(&flows, &client, sizeof(struct sockaddr_in), &backend,
                                        sizeof(struct sockaddr_in), fd, 1);
  ASSERT_TRUE(flow != nullptr);
  ASSERT_TRUE(flow->id != 0U);
  const size_t slot = qsr_flow_table_slot_of(&flows, flow);

  const uint8_t cid[8] = {0xD0, 0, 0, 0, 0, 0, 0, 0};
  qsr_session_key_t alias = qsr_session_single_cid_key(cid, sizeof(cid));
  ASSERT_TRUE(qsr_session_table_put_owned(&sessions, &alias, &backend, sizeof(struct sockaddr_in), 1, slot,
                                          flow->id) == QSR_OK);
  qsr_session_key_t tuple = qsr_session_tuple_key(&client, sizeof(struct sockaddr_in));
  ASSERT_TRUE(qsr_session_table_put(&sessions, &tuple, &backend, sizeof(struct sockaddr_in), 1) == QSR_OK);

  /* now=100: both sessions are past the 60s idle timeout, but the flow saw
   * traffic at now=90, so the keepalive predicate must retain both (the alias
   * via its owner link, the tuple entry via the flow lookup fallback). */
  flow->last_seen = 90;
  qsr_session_keepalive_ctx_t ctx = {.flows = &flows, .now = 100, .idle_timeout_seconds = 60};
  ASSERT_TRUE(sweep_all(&sessions, 100, 60, qsr_runtime_session_keepalive, &ctx) == 0U);
  ASSERT_TRUE(qsr_session_table_get(&sessions, &alias) != nullptr);
  ASSERT_TRUE(qsr_session_table_get(&sessions, &tuple) != nullptr);

  /* Remove the flow (connection over): one idle period later both expire. */
  qsr_flow_table_remove(&flows, flow);
  ctx.now = 200;
  ASSERT_TRUE(sweep_all(&sessions, 200, 60, qsr_runtime_session_keepalive, &ctx) == 2U);
  ASSERT_TRUE(qsr_session_table_get(&sessions, &alias) == nullptr);

  qsr_flow_table_free(&flows);
  qsr_session_table_free(&sessions);
}

/*
 * A recycled flow slot must not keep a stale alias alive: the generation id
 * in the owner link has to mismatch after the slot is reused by a new flow.
 */
static void test_recycled_flow_slot_does_not_keep_alias(void) {
  qsr_session_table_t sessions;
  qsr_flow_table_t flows;
  ASSERT_TRUE(qsr_session_table_init(&sessions, 8U) == QSR_OK);
  ASSERT_TRUE(qsr_flow_table_init(&flows, 1U) == QSR_OK);

  struct sockaddr_storage client_a = make_v4(0x0100007fU, 50000U);
  struct sockaddr_storage client_b = make_v4(0x0100007fU, 50001U);
  struct sockaddr_storage backend = make_v4(0x0200007fU, 8443U);
  qsr_flow_t *flow_a =
      qsr_flow_table_put(&flows, &client_a, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in), dup(0), 1);
  ASSERT_TRUE(flow_a != nullptr);
  const uint64_t id_a = flow_a->id;
  const size_t slot_a = qsr_flow_table_slot_of(&flows, flow_a);

  const uint8_t cid[8] = {0xE0, 0, 0, 0, 0, 0, 0, 0};
  qsr_session_key_t alias = qsr_session_single_cid_key(cid, sizeof(cid));
  ASSERT_TRUE(qsr_session_table_put_owned(&sessions, &alias, &backend, sizeof(struct sockaddr_in), 1, slot_a, id_a) ==
              QSR_OK);

  /* Capacity 1: inserting client B evicts A and reuses its slot with a new id. */
  qsr_flow_t *flow_b =
      qsr_flow_table_put(&flows, &client_b, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in), dup(0),
                         50);
  ASSERT_TRUE(flow_b != nullptr);
  ASSERT_TRUE(qsr_flow_table_slot_of(&flows, flow_b) == slot_a);
  ASSERT_TRUE(flow_b->id != id_a);

  /* A's alias is idle-expired; B's fresh flow in the same slot must not save it. */
  qsr_session_keepalive_ctx_t ctx = {.flows = &flows, .now = 100, .idle_timeout_seconds = 60};
  ASSERT_TRUE(sweep_all(&sessions, 100, 60, qsr_runtime_session_keepalive, &ctx) == 1U);
  ASSERT_TRUE(qsr_session_table_get(&sessions, &alias) == nullptr);

  qsr_flow_table_free(&flows);
  qsr_session_table_free(&sessions);
}

void test_session_table(void) {
  test_put_get_roundtrip();
  test_invalid_keys_rejected();
  test_expire_preserves_probe_chain();
  test_lru_eviction_when_full();
  test_incremental_expire_respects_budget();
  test_cid_length_mask_tracks_inserted_lengths();
  test_incremental_expire_keep_callback();
  test_cid_length_mask_retires_stale_bits();
  test_flow_owned_alias_survives_active_flow();
  test_recycled_flow_slot_does_not_keep_alias();
  test_evict_if_returns_zero_when_empty();
  test_evict_if_all_clears_table();
  test_evict_if_none_keeps_table();
  test_evict_if_selective_preserves_others();
  test_short_cid_alias_rejected();
}
