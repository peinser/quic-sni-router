/*
 * qsr/flow_table.h: bounded table of per-client upstream flows. Each flow owns
 * an unconnected UDP socket used exclusively for one client tuple's traffic
 * toward its backend, so the backend sees a distinct router source port per
 * client and return datagrams arrive on the flow's own fd. That makes
 * backend-to-client demultiplexing exact for any number of concurrent QUIC
 * connections to the same backend, including clients that use zero-length or
 * rotated connection IDs (which carry no routable bits the router can see).
 *
 * Slot stability: a live flow never moves between slots, so a slot index can
 * be carried as epoll user data for the lifetime of the flow's fd. Lookups go
 * through a separate open-addressed index keyed by client tuple; deletion
 * reinserts the index probe cluster (same approach as qsr/session_table.h)
 * without touching the slots themselves.
 *
 * Ownership: the table owns every stored fd. Eviction, expiry, filtered
 * eviction, and qsr_flow_table_free all close fds; closing an fd also removes
 * it from any epoll set it was registered with.
 */
#ifndef QSR_FLOW_TABLE_H
#define QSR_FLOW_TABLE_H

#include "qsr/common.h"

#include <netinet/in.h>
#include <time.h>

typedef struct qsr_flow {
  bool used;
  int fd; /* unconnected UDP socket toward the backend; -1 when unused */
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len;
  struct sockaddr_storage backend_addr;
  socklen_t backend_addr_len;
  time_t last_seen;
} qsr_flow_t;

typedef struct qsr_flow_table {
  qsr_flow_t *flows;  /* slot-stable array of capacity entries */
  size_t *index;      /* open-addressed map client tuple -> slot + 1; 0 = empty */
  size_t *free_slots; /* stack of unused slot ids */
  size_t free_count;
  size_t capacity;
  size_t index_capacity;
  size_t count;
  size_t expire_cursor; /* over the flows array, incremental idle sweep */
  size_t evict_cursor;  /* over the flows array, for oldest-scan eviction */
} qsr_flow_table_t;

[[nodiscard]] qsr_status_t qsr_flow_table_init(qsr_flow_table_t *table, size_t capacity);
void qsr_flow_table_free(qsr_flow_table_t *table);

[[nodiscard]] qsr_flow_t *qsr_flow_table_get(const qsr_flow_table_t *table, const struct sockaddr_storage *client,
                                             socklen_t client_len);

/*
 * Insert a flow for `client` owning `fd`. If the tuple is already present, the
 * existing flow is updated in place (its previous fd is closed when different).
 * When the table is full, the oldest flow by last_seen is evicted to make
 * room. Returns the stored flow, or nullptr on invalid arguments; on nullptr
 * the caller keeps ownership of `fd`.
 */
[[nodiscard]] qsr_flow_t *qsr_flow_table_put(qsr_flow_table_t *table, const struct sockaddr_storage *client,
                                             socklen_t client_len, const struct sockaddr_storage *backend,
                                             socklen_t backend_len, int fd, time_t now);

/* Remove one flow and close its fd. `flow` must point into the table. */
void qsr_flow_table_remove(qsr_flow_table_t *table, const qsr_flow_t *flow);

/* Slot accessors for epoll dispatch. slot() returns nullptr for unused slots. */
[[nodiscard]] qsr_flow_t *qsr_flow_table_slot(const qsr_flow_table_t *table, size_t slot);
[[nodiscard]] size_t qsr_flow_table_slot_of(const qsr_flow_table_t *table, const qsr_flow_t *flow);

/* Evict the single oldest flow by last_seen (bounded scan). Returns the number
 * evicted (0 or 1). Used to reclaim an fd on EMFILE/ENFILE. */
size_t qsr_flow_table_evict_oldest(qsr_flow_table_t *table);

size_t qsr_flow_table_expire_incremental(qsr_flow_table_t *table, time_t now, time_t idle_timeout_seconds,
                                         size_t scan_budget);

/*
 * Walk all flows and remove (closing fds) every one for which pred returns
 * true. Used by hot reload to hard-cutover flows whose backend disappeared.
 * pred must not call back into the flow table.
 */
typedef bool (*qsr_flow_filter_fn)(const qsr_flow_t *flow, void *userdata);
size_t qsr_flow_table_evict_if(qsr_flow_table_t *table, qsr_flow_filter_fn pred, void *userdata);

#endif
