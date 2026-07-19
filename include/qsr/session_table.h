/*
 * qsr/session_table.h: bounded open-addressed hash table mapping client
 * tuples / observed QUIC CIDs to backend addresses. Backward-shift deletion
 * preserves probe-chain integrity (so qsr_session_table_get works correctly
 * after expire/evict sweeps).
 *
 * When the table is at capacity, qsr_session_table_put evicts the oldest
 * entry by last_seen to avoid an unbounded-growth DoS where an attacker
 * spams Initials to lock out legitimate clients.
 *
 * qsr_session_table_evict_if is used by the hot-reload procedure to do a
 * hard cutover (sessions whose backend disappeared from the new config).
 */
#ifndef QSR_SESSION_TABLE_H
#define QSR_SESSION_TABLE_H

#include "qsr/common.h"

#include <netinet/in.h>
#include <time.h>

typedef struct qsr_session_key {
  /* Layout chosen to minimize padding (~18 bytes recovered vs. naive order). */
  size_t dcid_len;
  size_t scid_len;
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len;
  bool has_tuple;
  bool has_cids;
  uint8_t dcid[QSR_MAX_QUIC_CID_LEN];
  uint8_t scid[QSR_MAX_QUIC_CID_LEN];
} qsr_session_key_t;

typedef struct qsr_session {
  bool used;
  qsr_session_key_t key;
  struct sockaddr_storage backend_addr;
  socklen_t backend_addr_len;
  time_t last_seen;
  /*
   * Optional owning flow, as slot + generation id. Lets the expiry sweep keep
   * CID aliases alive while the client's flow still carries traffic: the fast
   * path only refreshes the flow, so without this link every alias of a
   * long-lived connection would expire after idleTimeout and NAT rebinding
   * would stop working for connections older than that. owner_flow_id 0 means
   * no owner; the id disambiguates a recycled slot.
   */
  size_t owner_slot;
  uint64_t owner_flow_id;
} qsr_session_t;

typedef struct qsr_session_table {
  qsr_session_t *sessions;
  size_t capacity;
  size_t count;
  size_t expire_cursor;
  size_t evict_cursor;
  uint32_t cid_len_mask;
  /*
   * Accumulator for the next cid_len_mask: bits of surviving/inserted entries
   * observed during the current incremental sweep cycle. Swapped into
   * cid_len_mask when the cursor wraps, so stale length bits (from expired
   * sessions with unusual CID lengths) stop costing short-header scan probes
   * after at most one full sweep cycle.
   */
  uint32_t cid_len_mask_pending;
} qsr_session_table_t;

[[nodiscard]] qsr_status_t qsr_session_table_init(qsr_session_table_t *table, size_t capacity);
void qsr_session_table_free(qsr_session_table_t *table);
[[nodiscard]] qsr_session_t *qsr_session_table_get(const qsr_session_table_t *table, const qsr_session_key_t *key);
qsr_status_t qsr_session_table_put(qsr_session_table_t *table, const qsr_session_key_t *key,
                                   const struct sockaddr_storage *backend_addr, socklen_t backend_addr_len, time_t now);

/*
 * Like qsr_session_table_put, additionally recording the owning flow
 * (slot + generation id) on the entry. owner_flow_id 0 leaves any existing
 * owner untouched on update; non-zero overwrites it.
 */
qsr_status_t qsr_session_table_put_owned(qsr_session_table_t *table, const qsr_session_key_t *key,
                                         const struct sockaddr_storage *backend_addr, socklen_t backend_addr_len,
                                         time_t now, size_t owner_slot, uint64_t owner_flow_id);
qsr_session_key_t qsr_session_tuple_key(const struct sockaddr_storage *addr, socklen_t addr_len);
qsr_session_key_t qsr_session_cid_key(const uint8_t *dcid, size_t dcid_len, const uint8_t *scid, size_t scid_len);
qsr_session_key_t qsr_session_single_cid_key(const uint8_t *cid, size_t cid_len);
size_t qsr_session_table_expire(qsr_session_table_t *table, time_t now, time_t idle_timeout_seconds);

/*
 * Returns true if an idle-expired session should be kept alive (its last_seen
 * is refreshed to `now` instead of deleting). Called only for entries whose
 * idle timeout already elapsed, i.e. at sweep rate, never per packet.
 * Must not mutate the session table.
 */
typedef bool (*qsr_session_keep_fn)(const qsr_session_t *session, void *userdata);

size_t qsr_session_table_expire_incremental(qsr_session_table_t *table, time_t now, time_t idle_timeout_seconds,
                                            size_t scan_budget, qsr_session_keep_fn keep, void *keep_userdata);
[[nodiscard]] uint32_t qsr_session_table_cid_len_mask(const qsr_session_table_t *table);

/*
 * Walk the session table and remove every entry for which pred returns true.
 * Uses backward-shift deletion in place so probe-chain integrity is preserved
 * after the sweep. Returns the number of sessions evicted.
 *
 * pred must not call back into the session table.
 */
typedef bool (*qsr_session_filter_fn)(const qsr_session_t *session, void *userdata);
size_t qsr_session_table_evict_if(qsr_session_table_t *table, qsr_session_filter_fn pred, void *userdata);

#endif
