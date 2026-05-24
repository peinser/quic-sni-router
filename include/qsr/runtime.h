/*
 * qsr/runtime.h: dataplane lifecycle: owns the live qsr_config_t and the
 * qsr_session_table_t, plus the inotify-driven hot-reload mechanism that
 * mutates them. Hiding this behind a module lets qsr/udp.h stay focused on
 * packet I/O.
 *
 * Single-threaded by design: every mutator (poll, reload, eviction) and every
 * reader (packet routing) runs on the dataplane thread, so the route-table
 * swap during reload is a single struct assignment with no concurrent reader.
 */
#ifndef QSR_RUNTIME_H
#define QSR_RUNTIME_H

#include "qsr/config.h"
#include "qsr/route_table.h"
#include "qsr/session_table.h"

/*
 * Runtime state for the dataplane: live config + session table, plus the
 * hot-reload machinery that mutates them. Owning these together lets us hide
 * the reload state machine from udp.c, which can stay focused on packet I/O.
 *
 * Single-threaded by design: every mutator (qsr_runtime_poll, eviction) and
 * every reader (qsr_session_table_get, route lookup in handle_packet) runs on
 * the dataplane thread.
 */
typedef struct qsr_runtime {
  qsr_config_t config;
  qsr_session_table_t sessions;
  const char *config_path; /* nullptr = no hot reload */
  int inotify_fd;          /* -1 = no watch (defaults-only run, or setup failed) */
} qsr_runtime_t;

/*
 * Initialize from a pre-loaded config. `config_path` (optional) enables
 * inotify-driven hot reload by watching the directory that contains the file.
 * On failure the runtime is left in a safe-to-free state.
 */
[[nodiscard]] qsr_status_t qsr_runtime_init(qsr_runtime_t *runtime, const qsr_config_t *config,
                                            const char *config_path);

void qsr_runtime_free(qsr_runtime_t *runtime);

/* Returns the inotify fd for inclusion in the dataplane's epoll set, or -1. */
[[nodiscard]] int qsr_runtime_inotify_fd(const qsr_runtime_t *runtime);

/*
 * Called every dataplane iteration. Cheap no-op when nothing changed.
 *
 * If inotify reports a config-directory change, re-reads the file, validates
 * and DNS-resolves the new config, evicts sessions whose backend disappeared
 * (hard cutover), and atomically swaps in the new routes + idle timeout.
 * `listen.udp` and `sessions.maxSessions` changes are ignored with a logged
 * warning — they require a process restart.
 *
 * If parse or resolve fails, the previous config keeps serving traffic.
 */
void qsr_runtime_poll(qsr_runtime_t *runtime);

/*
 * Log one `<prefix> route <sni> -> <ip:port>` line per resolved route in the
 * table, on stderr. Cheap and called only at startup and (for the diff) on
 * reload. Useful for ops audit of "when did this route appear?".
 */
void qsr_runtime_log_routes(const char *prefix, const qsr_route_table_t *routes);

#endif
