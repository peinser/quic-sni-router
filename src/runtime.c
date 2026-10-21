#include "qsr/runtime.h"

#include "qsr/hash.h"
#include "qsr/route_table.h"

#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
typedef struct qsr_reload_job {
  pthread_t thread;
  atomic_bool done;
  const char *path;
  qsr_status_t status;
  qsr_config_t config;
  struct timespec started;
} qsr_reload_job_t;

#include <sys/inotify.h>
#endif

/*
 * Format a (resolved) backend sockaddr into "ip:port" for logging. Best-effort:
 * on failure we return "?" rather than abort, since logging is not load-bearing.
 */
static void format_backend(const struct sockaddr_storage *addr, socklen_t addr_len, char *out, size_t out_len) {
  char host[INET6_ADDRSTRLEN] = {0};
  uint16_t port = 0U;
  if (addr->ss_family == AF_INET && addr_len >= sizeof(struct sockaddr_in)) {
    const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
    (void)inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
    port = ntohs(sin->sin_port);
  } else if (addr->ss_family == AF_INET6 && addr_len >= sizeof(struct sockaddr_in6)) {
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
    (void)inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
    port = ntohs(sin6->sin6_port);
  } else {
    (void)snprintf(out, out_len, "?");
    return;
  }
  if (addr->ss_family == AF_INET6) {
    (void)snprintf(out, out_len, "[%s]:%u", host, port);
  } else {
    (void)snprintf(out, out_len, "%s:%u", host, port);
  }
}

/*
 * Find a route in `table` by SNI (already-normalized, since the table stores
 * the lowercased form). Returns nullptr if not present. O(N) — fine for
 * reload-time diff logging where N is bounded by QSR_MAX_ROUTES (1024).
 */
static const qsr_route_t *find_route_by_sni(const qsr_route_table_t *table, const char *sni) {
  for (size_t i = 0U; i < table->count; i++) {
    if (strcmp(table->routes[i].sni, sni) == 0) {
      return &table->routes[i];
    }
  }
  return nullptr;
}

void qsr_runtime_log_routes(const char *prefix, const qsr_route_table_t *routes) {
  if (routes == nullptr) {
    return;
  }
  for (size_t i = 0U; i < routes->count; i++) {
    char addr[INET6_ADDRSTRLEN + 8] = "?";
    if (routes->routes[i].backend_resolved) {
      format_backend(&routes->routes[i].backend_addr, routes->routes[i].backend_addr_len, addr, sizeof(addr));
    }
    (void)fprintf(stderr, "%s route %s -> %s\n", prefix, routes->routes[i].sni, addr);
  }
}

static void log_route_diff(const qsr_route_table_t *old_routes, const qsr_route_table_t *new_routes) {
  size_t added = 0U;
  size_t removed = 0U;
  size_t changed = 0U;
  size_t unchanged = 0U;
  /*
   * Routes in NEW: classify as added (not in old), changed (in old with a
   * different backend), or unchanged. Quadratic in route count but bounded
   * by QSR_MAX_ROUTES only runs on reload, not per packet.
   */
  for (size_t i = 0U; i < new_routes->count; i++) {
    const qsr_route_t *n = &new_routes->routes[i];
    const qsr_route_t *o = find_route_by_sni(old_routes, n->sni);
    char new_addr[INET6_ADDRSTRLEN + 8] = "?";
    if (n->backend_resolved) {
      format_backend(&n->backend_addr, n->backend_addr_len, new_addr, sizeof(new_addr));
    }
    if (o == nullptr) {
      (void)fprintf(stderr, "reload: + route %s -> %s\n", n->sni, new_addr);
      added++;
    } else if (n->backend_addr_len != o->backend_addr_len ||
               memcmp(&n->backend_addr, &o->backend_addr, n->backend_addr_len) != 0) {
      char old_addr[INET6_ADDRSTRLEN + 8] = "?";
      if (o->backend_resolved) {
        format_backend(&o->backend_addr, o->backend_addr_len, old_addr, sizeof(old_addr));
      }
      (void)fprintf(stderr, "reload: ~ route %s -> %s (was %s)\n", n->sni, new_addr, old_addr);
      changed++;
    } else {
      unchanged++;
    }
  }
  /* Routes in OLD not in NEW: removed. */
  for (size_t i = 0U; i < old_routes->count; i++) {
    const qsr_route_t *o = &old_routes->routes[i];
    if (find_route_by_sni(new_routes, o->sni) == nullptr) {
      char addr[INET6_ADDRSTRLEN + 8] = "?";
      if (o->backend_resolved) {
        format_backend(&o->backend_addr, o->backend_addr_len, addr, sizeof(addr));
      }
      (void)fprintf(stderr, "reload: - route %s (was %s)\n", o->sni, addr);
      removed++;
    }
  }
  (void)fprintf(stderr, "reload: route summary: +%zu ~%zu -%zu =%zu\n", added, changed, removed, unchanged);
}

#ifdef __linux__
/*
 * Watch completed writes and atomic replacements, including Kubernetes' ..data
 * swap. IN_MODIFY is deliberately excluded: a truncate-before-write is not a
 * completed configuration and an empty intermediate file would remove routes.
 */
[[nodiscard]] static int setup_inotify_watch(const char *config_path) {
  if (config_path == nullptr) {
    return -1;
  }
  const int ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  if (ifd < 0) {
    perror("inotify_init1");
    return -1;
  }
  char path_copy[PATH_MAX];
  const size_t path_len = strlen(config_path);
  if (path_len + 1U > sizeof(path_copy)) {
    (void)close(ifd);
    return -1;
  }
  memcpy(path_copy, config_path, path_len + 1U);
  const char *dir = dirname(path_copy); /* POSIX: may modify the buffer in place */
  const uint32_t mask = IN_MOVED_TO | IN_CLOSE_WRITE;
  if (inotify_add_watch(ifd, dir, mask) < 0) {
    (void)fprintf(stderr, "inotify_add_watch(%s): %s\n", dir, strerror(errno));
    (void)close(ifd);
    return -1;
  }
  (void)fprintf(stderr, "quic-sni-router: hot-reload watching %s\n", dir);
  return ifd;
}

/*
 * Drain queued inotify events without blocking. Returns true if any events
 * matched the config filename or Kubernetes' ..data replacement. Unrelated
 * files in the directory must not trigger DNS work or configuration changes.
 */
[[nodiscard]] static bool drain_inotify(int inotify_fd, const char *config_path) {
  if (inotify_fd < 0) {
    return false;
  }
  alignas(struct inotify_event) uint8_t buf[4096];
  bool any = false;
  const char *name = strrchr(config_path, '/');
  name = name == nullptr ? config_path : name + 1;
  for (;;) {
    const ssize_t n = read(inotify_fd, buf, sizeof(buf));
    if (n > 0) {
      for (size_t offset = 0; offset < (size_t)n;) {
        const struct inotify_event *event = (const struct inotify_event *)(buf + offset);
        if (event->len > 0 && (event->mask & (IN_MOVED_TO | IN_CLOSE_WRITE)) != 0 &&
            (strcmp(event->name, name) == 0 ||
             ((event->mask & IN_MOVED_TO) != 0 && strcmp(event->name, "..data") == 0))) {
          any = true;
        }
        if ((event->mask & IN_Q_OVERFLOW) != 0) {
          (void)fprintf(stderr, "reload: inotify overflow; keeping config until next completed update\n");
        }
        offset += sizeof(*event) + event->len;
      }
      continue;
    }
    /* EAGAIN/EWOULDBLOCK: no more events. Anything else: stop, log on next read. */
    return any;
  }
}

typedef struct reload_backend_sets {
  const qsr_route_table_t *old_routes;
  const qsr_route_table_t *new_routes;
} reload_backend_sets_t;

static bool should_evict_flow_on_reload(const qsr_flow_t *flow, void *userdata) {
  const reload_backend_sets_t *sets = userdata;
  /* Same hard-cutover rule as sessions: drop flows pinned to a backend that
   * the new config no longer mentions. Closing the flow's fd also removes it
   * from the dataplane's epoll set. */
  return qsr_route_table_has_backend(sets->old_routes, &flow->backend_addr, flow->backend_addr_len) &&
         !qsr_route_table_has_backend(sets->new_routes, &flow->backend_addr, flow->backend_addr_len);
}

static bool should_evict_on_reload(const qsr_session_t *session, void *userdata) {
  const reload_backend_sets_t *sets = userdata;
  /*
   * Every session entry's backend_addr points at one of the OLD configured
   * backends. Evict iff that backend is no longer in the NEW config.
   */
  return qsr_route_table_has_backend(sets->old_routes, &session->backend_addr, session->backend_addr_len) &&
         !qsr_route_table_has_backend(sets->new_routes, &session->backend_addr, session->backend_addr_len);
}

static void apply_reload(qsr_runtime_t *runtime, const qsr_config_t *candidate) {
  const qsr_config_t new_config = *candidate;
  if (strcmp(new_config.listen_udp, runtime->config.listen_udp) != 0) {
    (void)fprintf(stderr, "reload: listen.udp change ignored (requires restart): %s -> %s\n",
                  runtime->config.listen_udp, new_config.listen_udp);
  }
  if (new_config.max_sessions != runtime->config.max_sessions) {
    (void)fprintf(stderr, "reload: sessions.maxSessions change ignored (requires restart): %zu -> %zu\n",
                  runtime->config.max_sessions, new_config.max_sessions);
  }

  reload_backend_sets_t sets = {.old_routes = &runtime->config.routes, .new_routes = &new_config.routes};
  const size_t evicted = qsr_session_table_evict_if(&runtime->sessions, should_evict_on_reload, &sets);
  const size_t flows_evicted = qsr_flow_table_evict_if(&runtime->flows, should_evict_flow_on_reload, &sets);

  /* Per-route diff lines are emitted before the atomic swap so the log
   * narrative reads "here's what's about to change, then ok". */
  log_route_diff(&runtime->config.routes, &new_config.routes);
  if (evicted > 0U || flows_evicted > 0U) {
    (void)fprintf(stderr, "reload: %zu sessions and %zu flows evicted (backends removed)\n", evicted, flows_evicted);
  }

  if (runtime->config.cid_codec.enabled != new_config.cid_codec.enabled ||
      (new_config.cid_codec.enabled &&
       memcmp(runtime->config.cid_codec.key, new_config.cid_codec.key, sizeof(new_config.cid_codec.key)) != 0)) {
    (void)fprintf(stderr, "reload: cidEncoding updated (enabled=%d)\n", new_config.cid_codec.enabled ? 1 : 0);
  }
  if (runtime->config.log_connections != new_config.log_connections) {
    (void)fprintf(stderr, "reload: logging.connections=%s\n", new_config.log_connections ? "on" : "off");
  }

  /* Atomic from the dataplane's point of view: we're single-threaded. */
  runtime->config.routes = new_config.routes;
  runtime->config.idle_timeout_seconds = new_config.idle_timeout_seconds;
  runtime->config.cid_codec = new_config.cid_codec;
  runtime->config.quic_lb = new_config.quic_lb;
  runtime->config.log_connections = new_config.log_connections;
  (void)fprintf(stderr, "reload: ok (%zu routes total)\n", runtime->config.routes.count);
}

static void *load_candidate(void *userdata) {
  qsr_reload_job_t *job = userdata;
  job->status = qsr_config_load(job->path, &job->config);
  if (job->status == QSR_OK) {
    job->status = qsr_route_table_resolve(&job->config.routes);
  }
  atomic_store_explicit(&job->done, true, memory_order_release);
  return nullptr;
}
#endif /* __linux__ */

/*
 * Each QUIC connection creates roughly four session-table entries (forward
 * tuple, DCID alias, server-SCID alias, DCID+SCID pair) but exactly one flow,
 * so the flow table is sized at a quarter of maxSessions. The floor keeps
 * small dev configs usable.
 */
enum : size_t { QSR_FLOWS_PER_SESSION_DIVISOR = 4U };
enum : size_t { QSR_FLOW_CAPACITY_MIN = 256U };

qsr_status_t qsr_runtime_init(qsr_runtime_t *runtime, const qsr_config_t *config, const char *config_path) {
  if (runtime == nullptr || config == nullptr) {
    return QSR_ERR_INVALID;
  }
  runtime->config = *config;
  runtime->sessions = (qsr_session_table_t){0};
  runtime->flows = (qsr_flow_table_t){0};
  runtime->config_path = config_path;
  runtime->inotify_fd = -1;
  runtime->reload_job = nullptr;
  runtime->reload_pending = false;
  (void)qsr_hash_bytes("", 0); /* Seed before the resolver worker can hash routes. */
  qsr_status_t status = qsr_session_table_init(&runtime->sessions, runtime->config.max_sessions);
  if (status != QSR_OK) {
    return status;
  }
  size_t flow_capacity = runtime->config.max_sessions / QSR_FLOWS_PER_SESSION_DIVISOR;
  if (flow_capacity < QSR_FLOW_CAPACITY_MIN) {
    flow_capacity = QSR_FLOW_CAPACITY_MIN;
  }
  status = qsr_flow_table_init(&runtime->flows, flow_capacity);
  if (status != QSR_OK) {
    qsr_session_table_free(&runtime->sessions);
    return status;
  }
#ifdef __linux__
  runtime->inotify_fd = setup_inotify_watch(config_path);
#else
  (void)config_path;
#endif
  return QSR_OK;
}

void qsr_runtime_free(qsr_runtime_t *runtime) {
  if (runtime == nullptr) {
    return;
  }
#ifdef __linux__
  if (runtime->reload_job != nullptr) {
    (void)pthread_join(runtime->reload_job->thread, nullptr);
    free(runtime->reload_job);
    runtime->reload_job = nullptr;
  }
  if (runtime->inotify_fd >= 0) {
    (void)close(runtime->inotify_fd);
    runtime->inotify_fd = -1;
  }
#endif
  qsr_flow_table_free(&runtime->flows);
  qsr_session_table_free(&runtime->sessions);
}

int qsr_runtime_inotify_fd(const qsr_runtime_t *runtime) { return runtime == nullptr ? -1 : runtime->inotify_fd; }

bool qsr_runtime_session_keepalive(const qsr_session_t *session, void *userdata) {
  const qsr_session_keepalive_ctx_t *ctx = userdata;
  const qsr_flow_t *flow = nullptr;
  if (session->owner_flow_id != 0U) {
    const qsr_flow_t *candidate = qsr_flow_table_slot(ctx->flows, session->owner_slot);
    if (candidate != nullptr && candidate->id == session->owner_flow_id) {
      flow = candidate;
    }
  } else if (session->key.has_tuple && !session->key.has_cids) {
    flow = qsr_flow_table_get(ctx->flows, &session->key.client_addr, session->key.client_addr_len);
  }
  return flow != nullptr && ctx->now - flow->last_seen < ctx->idle_timeout_seconds;
}

/*
 * Conceptually a mutator (publishes a candidate which writes runtime
 * fields), but on non-Linux platforms the body short-circuits and the compiler
 * only sees reads silence the resulting constness warning.
 */
/* cppcheck-suppress constParameterPointer ; mutator on __linux__ */
void qsr_runtime_poll(qsr_runtime_t *runtime) {
  if (runtime == nullptr) {
    return;
  }
#ifdef __linux__
  if (runtime->inotify_fd < 0 || runtime->config_path == nullptr) {
    return;
  }
  runtime->reload_pending |= drain_inotify(runtime->inotify_fd, runtime->config_path);
  qsr_reload_job_t *job = runtime->reload_job;
  if (job != nullptr && atomic_load_explicit(&job->done, memory_order_acquire)) {
    (void)pthread_join(job->thread, nullptr);
    if (!runtime->reload_pending) {
      if (job->status == QSR_OK) {
        apply_reload(runtime, &job->config);
      } else {
        (void)fprintf(stderr, "reload: load/resolve failed (%d); keeping previous config\n", (int)job->status);
      }
    }
    struct timespec finished;
    (void)clock_gettime(CLOCK_MONOTONIC, &finished);
    (void)fprintf(stderr, "reload: candidate completed in %.3fs\n",
                  (double)(finished.tv_sec - job->started.tv_sec) +
                      (double)(finished.tv_nsec - job->started.tv_nsec) / 1e9);
    free(job);
    runtime->reload_job = nullptr;
  }
  if (runtime->reload_pending && runtime->reload_job == nullptr) {
    qsr_reload_job_t *next = calloc(1, sizeof(*next));
    if (next == nullptr) {
      /* cppcheck-suppress memleak ; next is nullptr: calloc failed, nothing to free. */
      return;
    }
    next->path = runtime->config_path;
    atomic_init(&next->done, false);
    (void)clock_gettime(CLOCK_MONOTONIC, &next->started);
    const int error = pthread_create(&next->thread, nullptr, load_candidate, next);
    if (error != 0) {
      (void)fprintf(stderr, "reload: worker start failed: %s\n", strerror(error));
      free(next);
      return;
    }
    runtime->reload_job = next;
    runtime->reload_pending = false;
  }
#endif
}
