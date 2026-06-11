#include "qsr/flow_table.h"

#include "qsr/hash.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum : size_t { QSR_FLOW_EVICT_SCAN_BUDGET = 4096U };

static bool client_valid(const struct sockaddr_storage *client, socklen_t client_len) {
  if (client == nullptr || client_len == 0U || client_len > sizeof(*client)) {
    return false;
  }
  return client->ss_family == AF_INET || client->ss_family == AF_INET6;
}

/*
 * One-pass hash over a length-prefixed serialization, mirroring the session
 * table's key hashing (see session_table.c for the collision rationale).
 */
static size_t tuple_hash(const struct sockaddr_storage *client, socklen_t client_len, size_t capacity) {
  uint8_t buf[1U + sizeof(*client)];
  buf[0] = (uint8_t)client_len;
  memcpy(buf + 1U, client, client_len);
  return (size_t)(qsr_hash_bytes(buf, 1U + (size_t)client_len) % capacity);
}

static bool tuple_equals(const qsr_flow_t *flow, const struct sockaddr_storage *client, socklen_t client_len) {
  return flow->client_addr_len == client_len && memcmp(&flow->client_addr, client, client_len) == 0;
}

qsr_status_t qsr_flow_table_init(qsr_flow_table_t *table, size_t capacity) {
  if (table == nullptr || capacity == 0U) {
    return QSR_ERR_INVALID;
  }
  memset(table, 0, sizeof(*table));
  table->flows = calloc(capacity, sizeof(*table->flows));
  /* 2x index keeps the open-addressing load factor at or below 0.5. */
  table->index = calloc(capacity * 2U, sizeof(*table->index));
  table->free_slots = calloc(capacity, sizeof(*table->free_slots));
  if (table->flows == nullptr || table->index == nullptr || table->free_slots == nullptr) {
    qsr_flow_table_free(table);
    return QSR_ERR_FULL;
  }
  table->capacity = capacity;
  table->index_capacity = capacity * 2U;
  for (size_t i = 0U; i < capacity; i++) {
    table->flows[i].fd = -1;
    table->free_slots[i] = capacity - 1U - i;
  }
  table->free_count = capacity;
  return QSR_OK;
}

void qsr_flow_table_free(qsr_flow_table_t *table) {
  if (table == nullptr) {
    return;
  }
  if (table->flows != nullptr) {
    for (size_t i = 0U; i < table->capacity; i++) {
      if (table->flows[i].used && table->flows[i].fd >= 0) {
        (void)close(table->flows[i].fd);
      }
    }
  }
  free(table->flows);
  free(table->index);
  free(table->free_slots);
  memset(table, 0, sizeof(*table));
}

/*
 * Find the index position holding `slot`, or the position where the tuple
 * would be inserted (first empty). Returns SIZE_MAX only if the index is
 * full and the tuple absent, which cannot happen at load factor <= 0.5.
 */
static size_t index_find(const qsr_flow_table_t *table, const struct sockaddr_storage *client, socklen_t client_len) {
  size_t pos = tuple_hash(client, client_len, table->index_capacity);
  for (size_t probes = 0U; probes < table->index_capacity; probes++) {
    const size_t stored = table->index[pos];
    if (stored == 0U) {
      return pos;
    }
    const qsr_flow_t *flow = &table->flows[stored - 1U];
    if (flow->used && tuple_equals(flow, client, client_len)) {
      return pos;
    }
    pos = (pos + 1U) % table->index_capacity;
  }
  return SIZE_MAX;
}

qsr_flow_t *qsr_flow_table_get(const qsr_flow_table_t *table, const struct sockaddr_storage *client,
                               socklen_t client_len) {
  if (table == nullptr || table->flows == nullptr || !client_valid(client, client_len)) {
    return nullptr;
  }
  const size_t pos = index_find(table, client, client_len);
  if (pos == SIZE_MAX || table->index[pos] == 0U) {
    return nullptr;
  }
  return &table->flows[table->index[pos] - 1U];
}

/*
 * Delete the index entry at `pos` and reinsert the following probe cluster so
 * lookups remain correct (same scheme as the session table's deletion).
 */
static void index_delete_at(qsr_flow_table_t *table, size_t pos) {
  table->index[pos] = 0U;
  size_t cursor = (pos + 1U) % table->index_capacity;
  while (table->index[cursor] != 0U) {
    const size_t slot = table->index[cursor] - 1U;
    table->index[cursor] = 0U;
    const qsr_flow_t *flow = &table->flows[slot];
    const size_t dest = index_find(table, &flow->client_addr, flow->client_addr_len);
    table->index[dest] = slot + 1U;
    cursor = (cursor + 1U) % table->index_capacity;
  }
}

static void remove_slot(qsr_flow_table_t *table, size_t slot) {
  qsr_flow_t *flow = &table->flows[slot];
  const size_t pos = index_find(table, &flow->client_addr, flow->client_addr_len);
  if (pos != SIZE_MAX && table->index[pos] != 0U) {
    index_delete_at(table, pos);
  }
  if (flow->fd >= 0) {
    (void)close(flow->fd);
  }
  memset(flow, 0, sizeof(*flow));
  flow->fd = -1;
  table->free_slots[table->free_count++] = slot;
  table->count--;
}

void qsr_flow_table_remove(qsr_flow_table_t *table, const qsr_flow_t *flow) {
  if (table == nullptr || table->flows == nullptr || flow == nullptr || !flow->used) {
    return;
  }
  const size_t slot = (size_t)(flow - table->flows);
  if (slot < table->capacity) {
    remove_slot(table, slot);
  }
}

size_t qsr_flow_table_evict_oldest(qsr_flow_table_t *table) {
  if (table == nullptr || table->flows == nullptr || table->capacity == 0U || table->count == 0U) {
    return 0U;
  }
  size_t victim = SIZE_MAX;
  time_t oldest = 0;
  const size_t scans = table->capacity < QSR_FLOW_EVICT_SCAN_BUDGET ? table->capacity : QSR_FLOW_EVICT_SCAN_BUDGET;
  for (size_t i = 0U; i < scans; i++) {
    const size_t slot = (table->evict_cursor + i) % table->capacity;
    if (table->flows[slot].used && (victim == SIZE_MAX || table->flows[slot].last_seen < oldest)) {
      victim = slot;
      oldest = table->flows[slot].last_seen;
    }
  }
  table->evict_cursor = (table->evict_cursor + scans) % table->capacity;
  if (victim == SIZE_MAX) {
    return 0U;
  }
  remove_slot(table, victim);
  return 1U;
}

qsr_flow_t *qsr_flow_table_put(qsr_flow_table_t *table, const struct sockaddr_storage *client, socklen_t client_len,
                               const struct sockaddr_storage *backend, socklen_t backend_len, int fd, time_t now) {
  if (table == nullptr || table->flows == nullptr || !client_valid(client, client_len) || backend == nullptr ||
      backend_len == 0U || backend_len > sizeof(*backend) || fd < 0) {
    return nullptr;
  }
  size_t pos = index_find(table, client, client_len);
  if (pos != SIZE_MAX && table->index[pos] != 0U) {
    qsr_flow_t *flow = &table->flows[table->index[pos] - 1U];
    if (flow->fd >= 0 && flow->fd != fd) {
      (void)close(flow->fd);
    }
    flow->fd = fd;
    memcpy(&flow->backend_addr, backend, sizeof(*backend));
    flow->backend_addr_len = backend_len;
    flow->last_seen = now;
    return flow;
  }
  if (table->free_count == 0U) {
    if (qsr_flow_table_evict_oldest(table) == 0U) {
      return nullptr;
    }
    /* Eviction reshuffled the index probe cluster; re-derive the insert spot. */
    pos = index_find(table, client, client_len);
  }
  if (pos == SIZE_MAX) {
    return nullptr;
  }
  const size_t slot = table->free_slots[--table->free_count];
  qsr_flow_t *flow = &table->flows[slot];
  memset(flow, 0, sizeof(*flow));
  flow->used = true;
  flow->fd = fd;
  memcpy(&flow->client_addr, client, sizeof(*client));
  flow->client_addr_len = client_len;
  memcpy(&flow->backend_addr, backend, sizeof(*backend));
  flow->backend_addr_len = backend_len;
  flow->last_seen = now;
  table->index[pos] = slot + 1U;
  table->count++;
  return flow;
}

qsr_flow_t *qsr_flow_table_slot(const qsr_flow_table_t *table, size_t slot) {
  if (table == nullptr || table->flows == nullptr || slot >= table->capacity || !table->flows[slot].used) {
    return nullptr;
  }
  return &table->flows[slot];
}

size_t qsr_flow_table_slot_of(const qsr_flow_table_t *table, const qsr_flow_t *flow) {
  return (size_t)(flow - table->flows);
}

size_t qsr_flow_table_expire_incremental(qsr_flow_table_t *table, time_t now, time_t idle_timeout_seconds,
                                         size_t scan_budget) {
  if (table == nullptr || table->flows == nullptr || scan_budget == 0U) {
    return 0U;
  }
  size_t expired = 0U;
  size_t scanned = 0U;
  while (scanned < scan_budget && scanned < table->capacity) {
    const size_t slot = table->expire_cursor;
    if (table->flows[slot].used && now - table->flows[slot].last_seen >= idle_timeout_seconds) {
      remove_slot(table, slot);
      expired++;
    }
    table->expire_cursor = (table->expire_cursor + 1U) % table->capacity;
    scanned++;
  }
  return expired;
}

size_t qsr_flow_table_evict_if(qsr_flow_table_t *table, qsr_flow_filter_fn pred, void *userdata) {
  if (table == nullptr || table->flows == nullptr || pred == nullptr) {
    return 0U;
  }
  size_t evicted = 0U;
  for (size_t slot = 0U; slot < table->capacity; slot++) {
    if (table->flows[slot].used && pred(&table->flows[slot], userdata)) {
      remove_slot(table, slot);
      evicted++;
    }
  }
  return evicted;
}
