#include "qsr/session_table.h"

#include "qsr/hash.h"

#include <stdlib.h>
#include <string.h>

static bool key_valid(const qsr_session_key_t *key) {
  if (key == nullptr || (!key->has_tuple && !key->has_cids) || key->dcid_len > sizeof(key->dcid) ||
      key->scid_len > sizeof(key->scid)) {
    return false;
  }
  if (key->has_tuple && (key->client_addr_len == 0U || key->client_addr_len > sizeof(key->client_addr) ||
                         !(key->client_addr.ss_family == AF_INET || key->client_addr.ss_family == AF_INET6))) {
    return false;
  }
  return !key->has_cids || key->dcid_len > 0U || key->scid_len > 0U;
}

static bool backend_valid(const struct sockaddr_storage *backend_addr, socklen_t backend_addr_len) {
  if (backend_addr == nullptr || backend_addr_len == 0U || backend_addr_len > sizeof(*backend_addr)) {
    return false;
  }
  return backend_addr->ss_family == AF_INET || backend_addr->ss_family == AF_INET6;
}

/*
 * Serialize the key into a contiguous buffer and hash in a single SipHash
 * pass (rather than chained calls per field). Chained-call hashing of
 * variable-length fields can leak structure that's exploitable for
 * collision attacks; one-pass over a length-prefixed serialization avoids
 * it. The serialization includes lengths so two keys that pack to the same
 * bytes for different reasons (e.g., empty tuple + N-byte cid vs. N-byte
 * tuple + empty cid) hash differently.
 *
 * Max sizes: 2 flag bytes + 128-byte sockaddr_storage + 4-byte len-prefix
 * + 20-byte dcid + 4 + 20-byte scid = under 192 bytes. Fixed stack buffer.
 */
static size_t key_hash(const qsr_session_key_t *key, size_t capacity) {
  uint8_t buf[192];
  size_t n = 0U;
  buf[n++] = key->has_tuple ? 1U : 0U;
  buf[n++] = key->has_cids ? 1U : 0U;
  if (key->has_tuple) {
    /* length prefix prevents tuple/cid boundary ambiguity */
    buf[n++] = (uint8_t)key->client_addr_len;
    memcpy(buf + n, &key->client_addr, key->client_addr_len);
    n += key->client_addr_len;
  }
  if (key->has_cids) {
    buf[n++] = (uint8_t)key->dcid_len;
    memcpy(buf + n, key->dcid, key->dcid_len);
    n += key->dcid_len;
    buf[n++] = (uint8_t)key->scid_len;
    memcpy(buf + n, key->scid, key->scid_len);
    n += key->scid_len;
  }
  return (size_t)(qsr_hash_bytes(buf, n) % capacity);
}

static bool key_equals(const qsr_session_key_t *a, const qsr_session_key_t *b) {
  if (a->has_tuple != b->has_tuple || a->has_cids != b->has_cids || a->client_addr_len != b->client_addr_len ||
      a->dcid_len != b->dcid_len || a->scid_len != b->scid_len) {
    return false;
  }
  if (a->has_tuple && memcmp(&a->client_addr, &b->client_addr, a->client_addr_len) != 0) {
    return false;
  }
  if (a->has_cids && (memcmp(a->dcid, b->dcid, a->dcid_len) != 0 || memcmp(a->scid, b->scid, a->scid_len) != 0)) {
    return false;
  }
  return true;
}

qsr_session_key_t qsr_session_tuple_key(const struct sockaddr_storage *addr, socklen_t addr_len) {
  qsr_session_key_t key = {0};
  if (addr != nullptr && addr_len <= sizeof(key.client_addr)) {
    key.has_tuple = true;
    memcpy(&key.client_addr, addr, addr_len);
    key.client_addr_len = addr_len;
  }
  return key;
}

qsr_session_key_t qsr_session_cid_key(const uint8_t *dcid, size_t dcid_len, const uint8_t *scid, size_t scid_len) {
  qsr_session_key_t key = {0};
  if (dcid_len <= sizeof(key.dcid) && scid_len <= sizeof(key.scid) && (dcid_len > 0U || scid_len > 0U) &&
      (dcid_len == 0U || dcid != nullptr) && (scid_len == 0U || scid != nullptr)) {
    key.has_cids = true;
    if (dcid_len > 0U) {
      memcpy(key.dcid, dcid, dcid_len);
    }
    if (scid_len > 0U) {
      memcpy(key.scid, scid, scid_len);
    }
    key.dcid_len = dcid_len;
    key.scid_len = scid_len;
  }
  return key;
}

qsr_session_key_t qsr_session_single_cid_key(const uint8_t *cid, size_t cid_len) {
  /*
   * Reject CIDs below the minimum: storing a single-CID alias shorter than
   * QSR_MIN_LEARNED_CID_LEN enables a short-header false-match attack
   * (see common.h for the math). Returns an all-zero (invalid) key so the
   * caller's put/get fails with QSR_ERR_INVALID rather than silently
   * inserting an exploitable short alias.
   */
  if (cid_len < QSR_MIN_LEARNED_CID_LEN) {
    return (qsr_session_key_t){0};
  }
  return qsr_session_cid_key(cid, cid_len, nullptr, 0U);
}

qsr_status_t qsr_session_table_init(qsr_session_table_t *table, size_t capacity) {
  if (table == nullptr || capacity == 0U) {
    return QSR_ERR_INVALID;
  }
  table->sessions = calloc(capacity, sizeof(*table->sessions));
  if (table->sessions == nullptr) {
    return QSR_ERR_FULL;
  }
  table->capacity = capacity;
  table->count = 0U;
  return QSR_OK;
}

void qsr_session_table_free(qsr_session_table_t *table) {
  if (table == nullptr) {
    return;
  }
  free(table->sessions);
  table->sessions = nullptr;
  table->capacity = 0U;
  table->count = 0U;
}

qsr_session_t *qsr_session_table_get(const qsr_session_table_t *table, const qsr_session_key_t *key) {
  if (table == nullptr || table->sessions == nullptr || table->capacity == 0U || !key_valid(key)) {
    return nullptr;
  }
  size_t index = key_hash(key, table->capacity);
  for (size_t probes = 0U; probes < table->capacity; probes++) {
    qsr_session_t *session = &table->sessions[index];
    if (!session->used) {
      return nullptr;
    }
    if (key_equals(&session->key, key)) {
      return session;
    }
    index = (index + 1U) % table->capacity;
  }
  return nullptr;
}

/*
 * Backward-shift deletion: remove the entry at `index` and pull subsequent
 * entries up until probe-chain integrity is restored. Preserves correctness
 * for open addressing better than a zero-fill, which would orphan keys whose
 * hash placed them before the removed slot.
 *
 * Returns the index the caller should re-examine: the slot that originally
 * sat at `index` now holds a (possibly expired/evictable) shifted entry, so
 * a sweeping caller should not advance past it on this iteration.
 */
static size_t table_delete_at(qsr_session_table_t *table, size_t index) {
  size_t cursor = index;
  for (;;) {
    const size_t next = (cursor + 1U) % table->capacity;
    if (!table->sessions[next].used) {
      memset(&table->sessions[cursor], 0, sizeof(table->sessions[cursor]));
      break;
    }
    /*
     * Backward-shift validity: we can move the entry at `next` to `cursor`
     * only if `cursor` is still on its forward probe walk from its natural
     * slot. Concretely: cursor must be strictly closer to `natural` than
     * `next` is, measured by forward distance modulo capacity. If `cursor`
     * is at-or-past `next` (which includes the case where `next` is at its
     * own home, distance==0), moving would put the entry on the wrong side
     * of its natural slot — future lookups starting from natural would
     * walk forward and never reach it.
     */
    const size_t natural = key_hash(&table->sessions[next].key, table->capacity);
    const size_t cursor_dist = (cursor + table->capacity - natural) % table->capacity;
    const size_t next_dist = (next + table->capacity - natural) % table->capacity;
    if (cursor_dist >= next_dist) {
      memset(&table->sessions[cursor], 0, sizeof(table->sessions[cursor]));
      break;
    }
    table->sessions[cursor] = table->sessions[next];
    cursor = next;
  }
  table->count--;
  return index;
}

/*
 * Evict the oldest session by last_seen. O(capacity); only called from the
 * insertion slow path when the table is at capacity. Avoids a unbounded-growth
 * DoS where an attacker spams Initials to fill the table and lock out legitimate
 * clients.
 */
static void evict_oldest(qsr_session_table_t *table) {
  if (table->count == 0U) {
    return;
  }
  size_t victim = SIZE_MAX;
  time_t oldest = 0;
  for (size_t i = 0U; i < table->capacity; i++) {
    if (table->sessions[i].used && (victim == SIZE_MAX || table->sessions[i].last_seen < oldest)) {
      victim = i;
      oldest = table->sessions[i].last_seen;
    }
  }
  if (victim == SIZE_MAX) {
    return;
  }
  (void)table_delete_at(table, victim);
}

qsr_status_t qsr_session_table_put(qsr_session_table_t *table, const qsr_session_key_t *key,
                                   const struct sockaddr_storage *backend_addr, socklen_t backend_addr_len, time_t now) {
  if (table == nullptr || table->sessions == nullptr || table->capacity == 0U || !key_valid(key) ||
      !backend_valid(backend_addr, backend_addr_len)) {
    return QSR_ERR_INVALID;
  }
  /*
   * Single combined walk: looks for an existing key (update in place) and
   * the first empty slot (insert) in one pass. Previously this function
   * called qsr_session_table_get first and then did its own probe walk —
   * two hash computations and two probe walks per put.
   *
   * If the walk completes without finding either (table fully occupied and
   * no key match), we evict the oldest and walk once more. Bounded at
   * exactly two walks; the second is guaranteed to find an empty slot
   * because eviction freed at least one.
   */
  for (int attempt = 0; attempt < 2; attempt++) {
    size_t index = key_hash(key, table->capacity);
    for (size_t probes = 0U; probes < table->capacity; probes++) {
      qsr_session_t *session = &table->sessions[index];
      if (!session->used) {
        session->used = true;
        session->key = *key;
        memcpy(&session->backend_addr, backend_addr, sizeof(*backend_addr));
        session->backend_addr_len = backend_addr_len;
        session->last_seen = now;
        table->count++;
        return QSR_OK;
      }
      if (key_equals(&session->key, key)) {
        memcpy(&session->backend_addr, backend_addr, sizeof(*backend_addr));
        session->backend_addr_len = backend_addr_len;
        session->last_seen = now;
        return QSR_OK;
      }
      index = (index + 1U) % table->capacity;
    }
    /* Walked every slot: no match, no empty. Evict and retry once. */
    if (attempt == 0) {
      evict_oldest(table);
    }
  }
  return QSR_ERR_FULL;
}

size_t qsr_session_table_expire(qsr_session_table_t *table, time_t now, time_t idle_timeout_seconds) {
  if (table == nullptr || table->sessions == nullptr || table->capacity == 0U) {
    return 0U;
  }
  size_t expired = 0U;
  size_t i = 0U;
  /*
   * Walk and delete in place. After deletion the shifted entry sits at the
   * same index, so we don't advance — it may itself be expired.
   */
  while (i < table->capacity) {
    if (table->sessions[i].used && now - table->sessions[i].last_seen >= idle_timeout_seconds) {
      (void)table_delete_at(table, i);
      expired++;
      continue;
    }
    i++;
  }
  return expired;
}

size_t qsr_session_table_evict_if(qsr_session_table_t *table, qsr_session_filter_fn pred, void *userdata) {
  if (table == nullptr || table->sessions == nullptr || table->capacity == 0U || pred == nullptr) {
    return 0U;
  }
  size_t evicted = 0U;
  size_t i = 0U;
  while (i < table->capacity) {
    if (table->sessions[i].used && pred(&table->sessions[i], userdata)) {
      (void)table_delete_at(table, i);
      evicted++;
      continue;
    }
    i++;
  }
  return evicted;
}
