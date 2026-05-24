#include "qsr/metrics.h"

#include <string.h>

void qsr_metrics_init(qsr_metrics_t *metrics) {
  if (metrics != NULL) {
    memset(metrics, 0, sizeof(*metrics));
  }
}
