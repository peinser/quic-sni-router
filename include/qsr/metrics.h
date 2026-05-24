/*
 * qsr/metrics.h: counter struct for dataplane observability.
 *
 * NOTE: as of pre-1.0 these counters are declared but not yet wired into the
 * dataplane or exposed via any endpoint. Tracked under "Metrics endpoint" in
 * ROADMAP.md.
 */
#ifndef QSR_METRICS_H
#define QSR_METRICS_H

#include <stdint.h>

typedef struct qsr_metrics {
  uint64_t datagrams_in;
  uint64_t datagrams_out;
  uint64_t parse_failures;
  uint64_t unknown_sni;
  uint64_t sessions_active;
} qsr_metrics_t;

void qsr_metrics_init(qsr_metrics_t *metrics);

#endif
