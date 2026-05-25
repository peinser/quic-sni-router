#include "qsr/route_table.h"

#include "qsr/hash.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>

static uint64_t hash_string(const char *value) {
  /*
   * Route lookups happen once per Initial. Inputs are config-controlled
   * (operator only) so the keyed-hash defense is less critical than for the
   * session table, but using the same hash everywhere keeps the codebase
   * to a single implementation and side-steps any future "what if an
   * attacker can influence a route name" concern.
   */
  return qsr_hash_bytes(value, strlen(value));
}

static bool normalize_hostname(const char *input, char *out, size_t out_len) {
  const size_t len = input == NULL ? 0U : strlen(input);
  if (len == 0U || len >= out_len || input[0] == '.' || input[len - 1U] == '.') {
    return false;
  }
  size_t label_len = 0U;
  for (size_t i = 0U; i < len; i++) {
    const unsigned char c = (unsigned char)input[i];
    if (c == '.') {
      if (label_len == 0U || label_len > 63U || out[i - 1U] == '-') {
        return false;
      }
      label_len = 0U;
      out[i] = '.';
      continue;
    }
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')) {
      return false;
    }
    if (label_len == 0U && c == '-') {
      return false;
    }
    out[i] = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    label_len++;
  }
  if (label_len == 0U || label_len > 63U || out[len - 1U] == '-') {
    return false;
  }
  out[len] = '\0';
  return true;
}

void qsr_route_table_init(qsr_route_table_t *table) {
  if (table == nullptr) {
    return;
  }
  memset(table, 0, sizeof(*table));
  for (size_t i = 0U; i < QSR_ROUTE_BUCKETS; i++) {
    table->buckets[i] = SIZE_MAX;
  }
}

qsr_status_t qsr_route_table_add(qsr_route_table_t *table, const char *sni, const char *host, uint16_t port) {
  if (table == nullptr || sni == nullptr || host == nullptr || port == 0U) {
    return QSR_ERR_INVALID;
  }
  if (table->count >= QSR_MAX_ROUTES) {
    return QSR_ERR_FULL;
  }
  char normalized[QSR_MAX_HOSTNAME_LEN + 1U] = {0};
  if (!normalize_hostname(sni, normalized, sizeof(normalized)) || strlen(host) > QSR_MAX_ADDR_LEN) {
    return QSR_ERR_INVALID;
  }

  if (qsr_route_table_lookup(table, normalized) != nullptr) {
    return QSR_ERR_INVALID;
  }

  size_t bucket = (size_t)(hash_string(normalized) % QSR_ROUTE_BUCKETS);
  for (size_t probes = 0U; probes < QSR_ROUTE_BUCKETS; probes++) {
    if (table->buckets[bucket] == SIZE_MAX) {
      qsr_route_t *route = &table->routes[table->count];
      const size_t sni_len = strlen(normalized);
      const size_t host_len = strlen(host);
      memcpy(route->sni, normalized, sni_len);
      route->sni[sni_len] = '\0';
      memcpy(route->host, host, host_len);
      route->host[host_len] = '\0';
      route->port = port;
      table->buckets[bucket] = table->count;
      table->count++;
      return QSR_OK;
    }
    bucket = (bucket + 1U) % QSR_ROUTE_BUCKETS;
  }
  return QSR_ERR_FULL;
}

const qsr_route_t *qsr_route_table_lookup(const qsr_route_table_t *table, const char *sni) {
  if (table == nullptr || sni == nullptr) {
    return nullptr;
  }
  char normalized[QSR_MAX_HOSTNAME_LEN + 1U] = {0};
  if (!normalize_hostname(sni, normalized, sizeof(normalized))) {
    return nullptr;
  }
  size_t bucket = (size_t)(hash_string(normalized) % QSR_ROUTE_BUCKETS);
  for (size_t probes = 0U; probes < QSR_ROUTE_BUCKETS; probes++) {
    const size_t route_index = table->buckets[bucket];
    if (route_index == SIZE_MAX) {
      return nullptr;
    }
    if (route_index < table->count && strcmp(table->routes[route_index].sni, normalized) == 0) {
      return &table->routes[route_index];
    }
    bucket = (bucket + 1U) % QSR_ROUTE_BUCKETS;
  }
  return nullptr;
}

bool qsr_route_table_has_backend(const qsr_route_table_t *table, const struct sockaddr_storage *addr,
                                 socklen_t addr_len) {
  if (table == nullptr || addr == nullptr || addr_len == 0U) {
    return false;
  }
  for (size_t i = 0U; i < table->count; i++) {
    const qsr_route_t *route = &table->routes[i];
    if (route->backend_resolved && route->backend_addr_len == addr_len &&
        memcmp(&route->backend_addr, addr, addr_len) == 0) {
      return true;
    }
  }
  return false;
}

qsr_status_t qsr_route_table_resolve(qsr_route_table_t *table) {
  if (table == nullptr) {
    return QSR_ERR_INVALID;
  }
  for (size_t i = 0U; i < table->count; i++) {
    qsr_route_t *route = &table->routes[i];
    char port[16] = {0};
    if (snprintf(port, sizeof(port), "%u", route->port) <= 0) {
      return QSR_ERR_INVALID;
    }

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV,
    };

    struct addrinfo *res = nullptr;
    const int gai = getaddrinfo(route->host, port, &hints, &res);
    if (gai != 0 || res == nullptr) {
      if (res != nullptr) {
        freeaddrinfo(res);
      }
      fprintf(stderr, "route resolve: %s: %s\n", route->host, gai_strerror(gai));
      return QSR_ERR_INVALID;
    }
    /*
     * Prefer the first result the resolver returned; on dual-stack hosts getaddrinfo's
     * default ordering follows RFC 6724 (matching IPv6 listener address scope first).
     * No retry loop here is intentional: configuration load is fail-closed so an
     * operator notices misconfiguration before the dataplane comes up.
     */
    if (res->ai_addrlen > sizeof(route->backend_addr)) {
      freeaddrinfo(res);
      return QSR_ERR_INVALID;
    }
    memset(&route->backend_addr, 0, sizeof(route->backend_addr));
    memcpy(&route->backend_addr, res->ai_addr, res->ai_addrlen);
    route->backend_addr_len = res->ai_addrlen;
    route->backend_resolved = true;
    freeaddrinfo(res);
  }
  return QSR_OK;
}
