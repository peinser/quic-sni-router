/*
 * qsr/config.h: runtime configuration loaded from a YAML file (or built from
 * defaults). Schema mirrors the chart's values.yaml 1:1: listen.udp,
 * sessions.idleTimeout, sessions.maxSessions, routes (SNI -> host:port).
 * Backed by libyaml; see src/config.c for the loader.
 */
#ifndef QSR_CONFIG_H
#define QSR_CONFIG_H

#include "qsr/route_table.h"

typedef struct qsr_config {
  char listen_udp[QSR_MAX_LISTEN_ADDR_LEN];
  uint32_t idle_timeout_seconds;
  size_t max_sessions;
  qsr_route_table_t routes;
} qsr_config_t;

void qsr_config_default(qsr_config_t *config);
[[nodiscard]] qsr_status_t qsr_config_load(const char *path, qsr_config_t *config);

#endif
