/*
 * qsr/udp.h:dataplane entry point. Binds the listen socket, sets up
 * SO_REUSEPORT (Linux) for multi-process scaling, drives the io_uring
 * recvmsg + sendmmsg loop, and delegates lifecycle (config load, session table,
 * hot reload) to qsr/runtime.h. SIGINT/SIGTERM trigger a graceful drain.
 */
#ifndef QSR_UDP_H
#define QSR_UDP_H

#include "qsr/config.h"

/*
 * Run the UDP dataplane. If config_path is non-NULL, the directory containing
 * the config file is watched via inotify and the routing table + idle timeout
 * are hot-reloaded whenever the file changes (e.g., a Kubernetes ConfigMap
 * update). Passing nullptr disables hot reload — useful for the no-arg
 * defaults path and for tests.
 */
[[nodiscard]] qsr_status_t qsr_udp_run(const qsr_config_t *config, const char *config_path);

#endif
