#include "qsr/flow_table.h"
#include "test_main.h"

#include <errno.h>
#include <fcntl.h>
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

/* A real fd the table can own and close; dup of stdin is the cheapest. */
static int make_fd(void) {
  const int fd = dup(0);
  ASSERT_TRUE(fd >= 0);
  return fd;
}

static bool fd_is_open(int fd) { return fcntl(fd, F_GETFD) >= 0 || errno != EBADF; }

static void test_put_get_roundtrip(void) {
  qsr_flow_table_t table;
  ASSERT_TRUE(qsr_flow_table_init(&table, 4U) == QSR_OK);

  struct sockaddr_storage client = make_v4(0x0100007fU, 50000U);
  struct sockaddr_storage backend = make_v4(0x0200007fU, 8443U);
  const int fd = make_fd();
  qsr_flow_t *flow =
      qsr_flow_table_put(&table, &client, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in), fd, 10);
  ASSERT_TRUE(flow != nullptr);
  ASSERT_TRUE(flow->fd == fd);
  ASSERT_TRUE(qsr_flow_table_get(&table, &client, sizeof(struct sockaddr_in)) == flow);
  ASSERT_TRUE(table.count == 1U);

  /* Slot accessors must agree with each other. */
  const size_t slot = qsr_flow_table_slot_of(&table, flow);
  ASSERT_TRUE(qsr_flow_table_slot(&table, slot) == flow);

  struct sockaddr_storage other = make_v4(0x0100007fU, 50001U);
  ASSERT_TRUE(qsr_flow_table_get(&table, &other, sizeof(struct sockaddr_in)) == nullptr);

  qsr_flow_table_free(&table);
  ASSERT_TRUE(!fd_is_open(fd));
}

static void test_put_existing_tuple_replaces_fd(void) {
  qsr_flow_table_t table;
  ASSERT_TRUE(qsr_flow_table_init(&table, 4U) == QSR_OK);

  struct sockaddr_storage client = make_v4(0x0100007fU, 50000U);
  struct sockaddr_storage backend_a = make_v4(0x0200007fU, 8443U);
  struct sockaddr_storage backend_b = make_v4(0x0300007fU, 8444U);
  const int fd_a = make_fd();
  const int fd_b = make_fd();
  const qsr_flow_t *flow =
      qsr_flow_table_put(&table, &client, sizeof(struct sockaddr_in), &backend_a, sizeof(struct sockaddr_in), fd_a, 1);
  ASSERT_TRUE(flow != nullptr);
  const qsr_flow_t *updated =
      qsr_flow_table_put(&table, &client, sizeof(struct sockaddr_in), &backend_b, sizeof(struct sockaddr_in), fd_b, 2);
  ASSERT_TRUE(updated == flow);
  ASSERT_TRUE(table.count == 1U);
  ASSERT_TRUE(flow->fd == fd_b);
  ASSERT_TRUE(!fd_is_open(fd_a));
  ASSERT_TRUE(memcmp(&flow->backend_addr, &backend_b, sizeof(struct sockaddr_in)) == 0);

  qsr_flow_table_free(&table);
}

static void test_remove_closes_fd_and_unlinks(void) {
  qsr_flow_table_t table;
  ASSERT_TRUE(qsr_flow_table_init(&table, 4U) == QSR_OK);

  struct sockaddr_storage client = make_v4(0x0100007fU, 50000U);
  struct sockaddr_storage backend = make_v4(0x0200007fU, 8443U);
  const int fd = make_fd();
  const qsr_flow_t *flow =
      qsr_flow_table_put(&table, &client, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in), fd, 1);
  ASSERT_TRUE(flow != nullptr);
  qsr_flow_table_remove(&table, flow);
  ASSERT_TRUE(table.count == 0U);
  ASSERT_TRUE(!fd_is_open(fd));
  ASSERT_TRUE(qsr_flow_table_get(&table, &client, sizeof(struct sockaddr_in)) == nullptr);

  qsr_flow_table_free(&table);
}

static void test_full_table_evicts_oldest(void) {
  qsr_flow_table_t table;
  ASSERT_TRUE(qsr_flow_table_init(&table, 4U) == QSR_OK);

  struct sockaddr_storage backend = make_v4(0x0200007fU, 8443U);
  int fds[5];
  struct sockaddr_storage clients[5];
  for (uint16_t i = 0U; i < 5U; i++) {
    clients[i] = make_v4(0x0100007fU, (uint16_t)(50000U + i));
    fds[i] = make_fd();
    const qsr_flow_t *flow = qsr_flow_table_put(&table, &clients[i], sizeof(struct sockaddr_in), &backend,
                                                sizeof(struct sockaddr_in), fds[i], (time_t)(10 + i));
    ASSERT_TRUE(flow != nullptr);
  }
  /* Capacity 4, 5 inserts: the oldest (first) flow must have been evicted. */
  ASSERT_TRUE(table.count == 4U);
  ASSERT_TRUE(qsr_flow_table_get(&table, &clients[0], sizeof(struct sockaddr_in)) == nullptr);
  ASSERT_TRUE(!fd_is_open(fds[0]));
  for (uint16_t i = 1U; i < 5U; i++) {
    ASSERT_TRUE(qsr_flow_table_get(&table, &clients[i], sizeof(struct sockaddr_in)) != nullptr);
  }

  qsr_flow_table_free(&table);
}

/*
 * Deleting an index entry must not orphan tuples whose probe walk crossed the
 * deleted position. Insert a batch, remove every other flow, and verify the
 * survivors are all still reachable.
 */
static void test_removal_preserves_probe_chains(void) {
  qsr_flow_table_t table;
  ASSERT_TRUE(qsr_flow_table_init(&table, 64U) == QSR_OK);

  struct sockaddr_storage backend = make_v4(0x0200007fU, 8443U);
  struct sockaddr_storage clients[48];
  for (uint16_t i = 0U; i < 48U; i++) {
    clients[i] = make_v4(0x0100007fU, (uint16_t)(40000U + i));
    ASSERT_TRUE(qsr_flow_table_put(&table, &clients[i], sizeof(struct sockaddr_in), &backend,
                                   sizeof(struct sockaddr_in), make_fd(), 1) != nullptr);
  }
  for (uint16_t i = 0U; i < 48U; i += 2U) {
    const qsr_flow_t *flow = qsr_flow_table_get(&table, &clients[i], sizeof(struct sockaddr_in));
    ASSERT_TRUE(flow != nullptr);
    qsr_flow_table_remove(&table, flow);
  }
  for (uint16_t i = 1U; i < 48U; i += 2U) {
    ASSERT_TRUE(qsr_flow_table_get(&table, &clients[i], sizeof(struct sockaddr_in)) != nullptr);
  }
  ASSERT_TRUE(table.count == 24U);

  qsr_flow_table_free(&table);
}

static void test_expire_incremental_respects_budget(void) {
  qsr_flow_table_t table;
  ASSERT_TRUE(qsr_flow_table_init(&table, 8U) == QSR_OK);

  struct sockaddr_storage backend = make_v4(0x0200007fU, 8443U);
  for (uint16_t i = 0U; i < 8U; i++) {
    struct sockaddr_storage client = make_v4(0x0100007fU, (uint16_t)(50000U + i));
    ASSERT_TRUE(qsr_flow_table_put(&table, &client, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in),
                                   make_fd(), 0) != nullptr);
  }
  /* All idle at t=100 with timeout 10; budget 4 expires at most 4 per call. */
  const size_t first = qsr_flow_table_expire_incremental(&table, 100, 10, 4U);
  ASSERT_TRUE(first == 4U);
  ASSERT_TRUE(table.count == 4U);
  const size_t second = qsr_flow_table_expire_incremental(&table, 100, 10, 8U);
  ASSERT_TRUE(second == 4U);
  ASSERT_TRUE(table.count == 0U);

  qsr_flow_table_free(&table);
}

static bool evict_backend_port(const qsr_flow_t *flow, void *userdata) {
  const uint16_t *port_be = userdata;
  const struct sockaddr_in *sin = (const struct sockaddr_in *)&flow->backend_addr;
  return sin->sin_port == *port_be;
}

static void test_evict_if_selective(void) {
  qsr_flow_table_t table;
  ASSERT_TRUE(qsr_flow_table_init(&table, 8U) == QSR_OK);

  struct sockaddr_storage backend_a = make_v4(0x0200007fU, 8443U);
  struct sockaddr_storage backend_b = make_v4(0x0300007fU, 8444U);
  struct sockaddr_storage client_a = make_v4(0x0100007fU, 50000U);
  struct sockaddr_storage client_b = make_v4(0x0100007fU, 50001U);
  const int fd_a = make_fd();
  ASSERT_TRUE(qsr_flow_table_put(&table, &client_a, sizeof(struct sockaddr_in), &backend_a, sizeof(struct sockaddr_in),
                                 fd_a, 1) != nullptr);
  ASSERT_TRUE(qsr_flow_table_put(&table, &client_b, sizeof(struct sockaddr_in), &backend_b, sizeof(struct sockaddr_in),
                                 make_fd(), 1) != nullptr);

  uint16_t doomed_port = 8443U;
  ASSERT_TRUE(qsr_flow_table_evict_if(&table, evict_backend_port, &doomed_port) == 1U);
  ASSERT_TRUE(table.count == 1U);
  ASSERT_TRUE(!fd_is_open(fd_a));
  ASSERT_TRUE(qsr_flow_table_get(&table, &client_a, sizeof(struct sockaddr_in)) == nullptr);
  ASSERT_TRUE(qsr_flow_table_get(&table, &client_b, sizeof(struct sockaddr_in)) != nullptr);

  qsr_flow_table_free(&table);
}

typedef struct close_capture {
  size_t calls;
  qsr_flow_close_reason_t last_reason;
  int last_fd;
} close_capture_t;

static void capture_close(const qsr_flow_t *flow, qsr_flow_close_reason_t reason, void *userdata) {
  close_capture_t *capture = userdata;
  capture->calls++;
  capture->last_reason = reason;
  capture->last_fd = flow->fd;
  /* The hook must run before the fd is closed so a logger can still resolve it. */
  ASSERT_TRUE(fd_is_open(flow->fd));
}

static void test_close_callback_reasons(void) {
  qsr_flow_table_t table;
  ASSERT_TRUE(qsr_flow_table_init(&table, 2U) == QSR_OK);
  close_capture_t capture = {0};
  table.on_close = capture_close;
  table.on_close_userdata = &capture;

  struct sockaddr_storage backend = make_v4(0x0200007fU, 8443U);

  /* Explicit remove. */
  struct sockaddr_storage c1 = make_v4(0x0100007fU, 50000U);
  const qsr_flow_t *f1 = qsr_flow_table_put(&table, &c1, sizeof(struct sockaddr_in), &backend,
                                            sizeof(struct sockaddr_in), make_fd(), 1);
  ASSERT_TRUE(f1 != nullptr);
  qsr_flow_table_remove(&table, f1);
  ASSERT_TRUE(capture.calls == 1U);
  ASSERT_TRUE(capture.last_reason == QSR_FLOW_CLOSE_REMOVED);

  /* Idle expiry. */
  ASSERT_TRUE(qsr_flow_table_put(&table, &c1, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in),
                                 make_fd(), 1) != nullptr);
  ASSERT_TRUE(qsr_flow_table_expire_incremental(&table, 100, 10, 2U) == 1U);
  ASSERT_TRUE(capture.calls == 2U);
  ASSERT_TRUE(capture.last_reason == QSR_FLOW_CLOSE_IDLE);

  /* Capacity eviction: table of 2, third distinct tuple evicts the oldest. */
  struct sockaddr_storage c2 = make_v4(0x0100007fU, 50001U);
  struct sockaddr_storage c3 = make_v4(0x0100007fU, 50002U);
  ASSERT_TRUE(qsr_flow_table_put(&table, &c1, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in),
                                 make_fd(), 1) != nullptr);
  ASSERT_TRUE(qsr_flow_table_put(&table, &c2, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in),
                                 make_fd(), 2) != nullptr);
  ASSERT_TRUE(qsr_flow_table_put(&table, &c3, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in),
                                 make_fd(), 3) != nullptr);
  ASSERT_TRUE(capture.calls == 3U);
  ASSERT_TRUE(capture.last_reason == QSR_FLOW_CLOSE_EVICTED);

  /* Shutdown: the two remaining flows fire the hook from free. */
  qsr_flow_table_free(&table);
  ASSERT_TRUE(capture.calls == 5U);
  ASSERT_TRUE(capture.last_reason == QSR_FLOW_CLOSE_SHUTDOWN);
}

static void test_invalid_arguments_rejected(void) {
  qsr_flow_table_t table;
  ASSERT_TRUE(qsr_flow_table_init(&table, 4U) == QSR_OK);
  ASSERT_TRUE(qsr_flow_table_init(nullptr, 4U) == QSR_ERR_INVALID);

  struct sockaddr_storage client = make_v4(0x0100007fU, 50000U);
  struct sockaddr_storage backend = make_v4(0x0200007fU, 8443U);
  struct sockaddr_storage bad = {0};
  ASSERT_TRUE(qsr_flow_table_put(&table, &bad, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in), 0,
                                 1) == nullptr);
  ASSERT_TRUE(qsr_flow_table_put(&table, &client, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in), -1,
                                 1) == nullptr);
  ASSERT_TRUE(qsr_flow_table_get(&table, &bad, sizeof(struct sockaddr_in)) == nullptr);
  ASSERT_TRUE(qsr_flow_table_slot(&table, 99U) == nullptr);

  qsr_flow_table_free(&table);
}

void test_flow_table(void) {
  test_put_get_roundtrip();
  test_put_existing_tuple_replaces_fd();
  test_remove_closes_fd_and_unlinks();
  test_full_table_evicts_oldest();
  test_removal_preserves_probe_chains();
  test_expire_incremental_respects_budget();
  test_evict_if_selective();
  test_close_callback_reasons();
  test_invalid_arguments_rejected();
}
