/*
 * qsr/route_table.h: bounded-capacity (QSR_MAX_ROUTES) SNI -> backend table
 * with open-addressed hash lookup. SNIs are normalized (lowercased, label-
 * validated) on insert and lookup so config and protocol forms compare equal.
 *
 * Backend hostnames are resolved once via getaddrinfo at startup and again
 * on every hot reload — the dataplane never blocks on DNS.
 *
 * Resolved backend addresses are also indexed, so qsr_route_table_has_backend
 * can be used on the dataplane hot path without scanning every route.
 */
#ifndef QSR_ROUTE_TABLE_H
#define QSR_ROUTE_TABLE_H

#include "qsr/common.h"

#include <netinet/in.h>

typedef struct qsr_route {
  char sni[QSR_MAX_HOSTNAME_LEN + 1U];
  char host[QSR_MAX_ADDR_LEN + 1U];
  uint16_t port;
  bool backend_resolved;
  struct sockaddr_storage backend_addr;
  socklen_t backend_addr_len;
} qsr_route_t;

typedef struct qsr_route_table {
  qsr_route_t routes[QSR_MAX_ROUTES];
  size_t buckets[QSR_ROUTE_BUCKETS];
  size_t backend_buckets[QSR_ROUTE_BUCKETS];
  size_t count;
} qsr_route_table_t;

void qsr_route_table_init(qsr_route_table_t *table);
[[nodiscard]] qsr_status_t qsr_route_table_add(qsr_route_table_t *table, const char *sni, const char *host,
                                               uint16_t port);
[[nodiscard]] const qsr_route_t *qsr_route_table_lookup(const qsr_route_table_t *table, const char *sni);
[[nodiscard]] qsr_status_t qsr_route_table_resolve(qsr_route_table_t *table);

/*
 * Returns true iff `addr` (of length `addr_len`) is a resolved backend of
 * some route in `table`. Used on the dataplane path to classify packet
 * direction and at hot-reload time to decide whether a session's pinned
 * backend is still part of the configured set.
 */
[[nodiscard]] bool qsr_route_table_has_backend(const qsr_route_table_t *table,
                                               const struct sockaddr_storage *addr, socklen_t addr_len);

#endif
