/*
 * qsr/metrics.h: counter struct for dataplane observability.
 *
 * Counters are reported at shutdown and on SIGUSR1. An HTTP/Prometheus endpoint
 * is not implemented; live snapshots use the bounded asynchronous log pipe.
 */
#ifndef QSR_METRICS_H
#define QSR_METRICS_H

#include <stdint.h>

typedef struct qsr_metrics {
  uint64_t datagrams_in;
  uint64_t datagrams_out;
  uint64_t parse_failures;
  uint64_t unknown_sni;
  uint64_t receive_truncations;
  uint64_t kernel_drops;
  uint64_t flow_open_failures;
  uint64_t flow_evictions;
  uint64_t send_drops;
  uint64_t send_errors[256]; /* Linux errno values; final slot includes larger values. */
  uint64_t gso_batches;
} qsr_metrics_t;

void qsr_metrics_init(qsr_metrics_t *metrics);

#endif
