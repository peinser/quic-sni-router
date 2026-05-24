#include "qsr/route_table.h"
#include "test_main.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static void test_add_lookup_normalizes_case(void) {
  qsr_route_table_t table;
  qsr_route_table_init(&table);
  ASSERT_TRUE(qsr_route_table_add(&table, "RVR-A.flightdeck.test", "127.0.0.1", 8443U) == QSR_OK);
  const qsr_route_t *route = qsr_route_table_lookup(&table, "rvr-a.flightdeck.test");
  ASSERT_TRUE(route != nullptr);
  ASSERT_TRUE(route->port == 8443U);
  /* Lookup by the original mixed case must also work (we normalize on lookup). */
  ASSERT_TRUE(qsr_route_table_lookup(&table, "RVR-A.FLIGHTDECK.TEST") == route);
}

static void test_resolve_local(void) {
  qsr_route_table_t table;
  qsr_route_table_init(&table);
  ASSERT_TRUE(qsr_route_table_add(&table, "rvr-a.flightdeck.test", "127.0.0.1", 8443U) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_resolve(&table) == QSR_OK);
  const qsr_route_t *route = qsr_route_table_lookup(&table, "rvr-a.flightdeck.test");
  ASSERT_TRUE(route != nullptr && route->backend_resolved);
}

static void test_rejects_duplicate(void) {
  qsr_route_table_t table;
  qsr_route_table_init(&table);
  ASSERT_TRUE(qsr_route_table_add(&table, "a.example.test", "127.0.0.1", 8443U) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_add(&table, "a.example.test", "127.0.0.1", 8443U) == QSR_ERR_INVALID);
}

static void test_rejects_malformed_sni(void) {
  qsr_route_table_t table;
  qsr_route_table_init(&table);
  /* Leading hyphen in a label is rejected by the hostname validator. */
  ASSERT_TRUE(qsr_route_table_add(&table, "-bad.flightdeck.test", "127.0.0.1", 8443U) == QSR_ERR_INVALID);
  /* Empty label. */
  ASSERT_TRUE(qsr_route_table_add(&table, "a..b", "127.0.0.1", 8443U) == QSR_ERR_INVALID);
  /* Trailing dot. */
  ASSERT_TRUE(qsr_route_table_add(&table, "a.b.", "127.0.0.1", 8443U) == QSR_ERR_INVALID);
}

static void test_rejects_unresolvable(void) {
  qsr_route_table_t table;
  qsr_route_table_init(&table);
  ASSERT_TRUE(qsr_route_table_add(&table, "a.example.test",
                                  "this-hostname-does-not-resolve-anywhere.invalid", 8443U) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_resolve(&table) == QSR_ERR_INVALID);
}

/*
 * Confirms QSR_MAX_ROUTES is enforced. We don't try to overflow the bucket
 * table (which is twice the route capacity) here; that would require coercing
 * collisions deliberately.
 */
static void test_rejects_when_full(void) {
  qsr_route_table_t table;
  qsr_route_table_init(&table);
  for (size_t i = 0U; i < QSR_MAX_ROUTES; i++) {
    char sni[64];
    (void)snprintf(sni, sizeof(sni), "host-%zu.example.test", i);
    ASSERT_TRUE(qsr_route_table_add(&table, sni, "127.0.0.1", 8443U) == QSR_OK);
  }
  ASSERT_TRUE(qsr_route_table_add(&table, "extra.example.test", "127.0.0.1", 8443U) == QSR_ERR_FULL);
}

static struct sockaddr_storage make_v4(uint32_t addr_be, uint16_t port_be) {
  struct sockaddr_storage ss = {0};
  struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = addr_be;
  sin->sin_port = port_be;
  return ss;
}

static void test_has_backend(void) {
  qsr_route_table_t table;
  qsr_route_table_init(&table);
  ASSERT_TRUE(qsr_route_table_add(&table, "a.example.test", "127.0.0.1", 8443U) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_resolve(&table) == QSR_OK);

  const struct sockaddr_storage matching = make_v4(0x0100007fU /* 127.0.0.1 */, htons(8443U));
  ASSERT_TRUE(qsr_route_table_has_backend(&table, &matching, sizeof(struct sockaddr_in)));

  /* Same IP, different port: not in the table. */
  const struct sockaddr_storage wrong_port = make_v4(0x0100007fU, htons(9999U));
  ASSERT_TRUE(!qsr_route_table_has_backend(&table, &wrong_port, sizeof(struct sockaddr_in)));

  /* Different IP, right port: not in the table. */
  const struct sockaddr_storage wrong_addr = make_v4(0x0200007fU /* 127.0.0.2 */, htons(8443U));
  ASSERT_TRUE(!qsr_route_table_has_backend(&table, &wrong_addr, sizeof(struct sockaddr_in)));

  /* Length mismatch: not in the table. */
  ASSERT_TRUE(!qsr_route_table_has_backend(&table, &matching, sizeof(struct sockaddr_in6)));

  /* Defensive: nullptr table / addr. */
  ASSERT_TRUE(!qsr_route_table_has_backend(nullptr, &matching, sizeof(struct sockaddr_in)));
  ASSERT_TRUE(!qsr_route_table_has_backend(&table, nullptr, sizeof(struct sockaddr_in)));
}

/*
 * Models the hot-reload eviction predicate end-to-end at the route layer:
 * a backend present in the OLD config but not the NEW config should be the
 * sole "evictable" address. Sessions to backends present in BOTH (preserved
 * routes) or NEITHER (reverse aliases / unknown) must not be classified as
 * evictable.
 */
static void test_reload_cutover_set_math(void) {
  qsr_route_table_t old_routes;
  qsr_route_table_t new_routes;
  qsr_route_table_init(&old_routes);
  qsr_route_table_init(&new_routes);
  ASSERT_TRUE(qsr_route_table_add(&old_routes, "kept.example.test", "127.0.0.1", 8443U) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_add(&old_routes, "removed.example.test", "127.0.0.2", 8444U) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_resolve(&old_routes) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_add(&new_routes, "kept.example.test", "127.0.0.1", 8443U) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_resolve(&new_routes) == QSR_OK);

  const struct sockaddr_storage kept_addr = make_v4(0x0100007fU, htons(8443U));
  const struct sockaddr_storage removed_addr = make_v4(0x0200007fU, htons(8444U));
  /* A reverse-alias backend_addr (a client tuple). The set test must NOT
   * classify this as evictable — it isn't in either route set. */
  const struct sockaddr_storage client_tuple = make_v4(0xc0a80164U /* 192.168.1.100 */, htons(54321U));

  /* Eviction rule: addr in OLD and NOT in NEW. */
  ASSERT_TRUE(qsr_route_table_has_backend(&old_routes, &kept_addr, sizeof(struct sockaddr_in)) &&
              qsr_route_table_has_backend(&new_routes, &kept_addr, sizeof(struct sockaddr_in)));
  ASSERT_TRUE(qsr_route_table_has_backend(&old_routes, &removed_addr, sizeof(struct sockaddr_in)) &&
              !qsr_route_table_has_backend(&new_routes, &removed_addr, sizeof(struct sockaddr_in)));
  ASSERT_TRUE(!qsr_route_table_has_backend(&old_routes, &client_tuple, sizeof(struct sockaddr_in)) &&
              !qsr_route_table_has_backend(&new_routes, &client_tuple, sizeof(struct sockaddr_in)));
}

void test_route_table(void) {
  test_add_lookup_normalizes_case();
  test_resolve_local();
  test_rejects_duplicate();
  test_rejects_malformed_sni();
  test_rejects_unresolvable();
  test_rejects_when_full();
  test_has_backend();
  test_reload_cutover_set_math();
}
