#include "qsr/quic_frames.h"
#include "qsr/route_table.h"
#include "qsr/session_table.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define BENCH_ITERS 1000000U

static uint64_t nanos(void) {
  struct timespec ts;
  (void)clock_gettime(CLOCK_MONOTONIC, &ts);
  return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static void print_rate(const char *name, uint64_t elapsed_ns, uint64_t iterations) {
  const double seconds = (double)elapsed_ns / 1000000000.0;
  const double rate = (double)iterations / seconds;
  printf("%-28s %10.2f ops/s  %8.2f ns/op\n", name, rate, (double)elapsed_ns / (double)iterations);
}

static bool bench_route_lookup(void) {
  qsr_route_table_t table;
  qsr_route_table_init(&table);
  for (size_t i = 0U; i < 256U; i++) {
    char sni[64];
    char host[64];
    (void)snprintf(sni, sizeof(sni), "rvr-%zu.flightdeck.example.com", i);
    (void)snprintf(host, sizeof(host), "127.0.0.%zu", (i % 250U) + 1U);
    (void)qsr_route_table_add(&table, sni, host, 8443U);
  }
  const uint64_t start = nanos();
  size_t hits = 0U;
  for (size_t i = 0U; i < BENCH_ITERS; i++) {
    if (qsr_route_table_lookup(&table, "rvr-128.flightdeck.example.com") != NULL) {
      hits++;
    }
  }
  const uint64_t elapsed = nanos() - start;
  if (hits != BENCH_ITERS) {
    fprintf(stderr, "route benchmark sanity check failed\n");
    return false;
  }
  print_rate("route hash lookup", elapsed, BENCH_ITERS);
  return true;
}

static bool bench_session_lookup(void) {
  qsr_session_table_t table;
  if (qsr_session_table_init(&table, 4096U) != QSR_OK) {
    fprintf(stderr, "session benchmark init failed\n");
    return false;
  }
  struct sockaddr_storage backend;
  memset(&backend, 0, sizeof(backend));
  backend.ss_family = AF_INET;
  qsr_session_key_t target;
  memset(&target, 0, sizeof(target));
  for (size_t i = 0U; i < 2048U; i++) {
    uint8_t cid[8] = {0};
    cid[0] = (uint8_t)i;
    cid[1] = (uint8_t)(i >> 8U);
    qsr_session_key_t key = qsr_session_single_cid_key(cid, sizeof(cid));
    if (i == 1024U) {
      target = key;
    }
    if (qsr_session_table_put(&table, &key, &backend, sizeof(struct sockaddr_in), 1) != QSR_OK) {
      fprintf(stderr, "session benchmark insert failed\n");
      qsr_session_table_free(&table);
      return false;
    }
  }
  const uint64_t start = nanos();
  size_t hits = 0U;
  for (size_t i = 0U; i < BENCH_ITERS; i++) {
    if (qsr_session_table_get(&table, &target) != NULL) {
      hits++;
    }
  }
  const uint64_t elapsed = nanos() - start;
  if (hits != BENCH_ITERS) {
    fprintf(stderr, "session benchmark sanity check failed\n");
    qsr_session_table_free(&table);
    return false;
  }
  print_rate("session cid lookup", elapsed, BENCH_ITERS);
  qsr_session_table_free(&table);
  return true;
}

static bool bench_crypto_extract(void) {
  uint8_t frame[256];
  memset(frame, 'a', sizeof(frame));
  frame[0] = 0x06U;
  frame[1] = 0x00U;
  frame[2] = 0x40U;
  frame[3] = 0x80U;
  const uint64_t start = nanos();
  size_t hits = 0U;
  for (size_t i = 0U; i < BENCH_ITERS; i++) {
    qsr_crypto_stream_t stream;
    qsr_crypto_stream_init(&stream);
    if (qsr_quic_extract_crypto(frame, 132U, &stream) == QSR_OK && stream.len == 128U) {
      hits++;
    }
  }
  const uint64_t elapsed = nanos() - start;
  if (hits != BENCH_ITERS) {
    fprintf(stderr, "crypto extract benchmark sanity check failed: %zu\n", hits);
    return false;
  }
  print_rate("crypto frame extraction", elapsed, BENCH_ITERS);
  return true;
}

int main(void) {
  printf("Synthetic dataplane CPU benchmarks (%u iterations)\n", BENCH_ITERS);
  bool ok = true;
  ok = bench_route_lookup() && ok;
  ok = bench_session_lookup() && ok;
  ok = bench_crypto_extract() && ok;
  printf("\nUser-space lookup/parsing costs only. Drive the live Linux UDP loop\n");
  printf("(recvmmsg/sendmmsg) with synthetic packets to measure end-to-end p99.\n");
  return ok ? 0 : 1;
}
