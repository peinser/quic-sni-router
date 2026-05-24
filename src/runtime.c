#include "qsr/runtime.h"

#include "qsr/route_table.h"

#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
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
 * Watch the directory containing the config file with inotify. The mask is
 * deliberately broad: Kubernetes ConfigMap updates atomically swap a `..data`
 * symlink in the mount directory (generating IN_MOVED_TO), while an editor
 * tends to atomic-rewrite via tmp + rename (IN_MOVED_TO) or truncate-and-write
 * (IN_MODIFY + IN_CLOSE_WRITE). We react to any of these, see drain_inotify
 * below for why we don't try to decode which file actually moved.
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
  const uint32_t mask = IN_MOVED_TO | IN_CREATE | IN_MODIFY | IN_CLOSE_WRITE | IN_DELETE;
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
 * were consumed (caller should trigger reload). We don't inspect event names:
 * the directory mask is narrow enough that any event there warrants a
 * re-read of the config file, and reading the actual file is cheap.
 */
[[nodiscard]] static bool drain_inotify(int inotify_fd) {
  if (inotify_fd < 0) {
    return false;
  }
  alignas(struct inotify_event) uint8_t buf[4096];
  bool any = false;
  for (;;) {
    const ssize_t n = read(inotify_fd, buf, sizeof(buf));
    if (n > 0) {
      any = true;
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

static bool should_evict_on_reload(const qsr_session_t *session, void *userdata) {
  const reload_backend_sets_t *sets = userdata;
  /*
   * Forward alias: backend_addr is one of the OLD configured backends. Evict
   * iff that backend is no longer in the NEW config.
   * Reverse alias: backend_addr is a client tuple (never a configured backend
   * in any version of the config). The first conjunct is false, so we keep it
   * untouched, the client will idle out naturally if its forward session was
   * evicted.
   */
  return qsr_route_table_has_backend(sets->old_routes, &session->backend_addr, session->backend_addr_len) &&
         !qsr_route_table_has_backend(sets->new_routes, &session->backend_addr, session->backend_addr_len);
}

static void reload_from_path(qsr_runtime_t *runtime) {
  qsr_config_t new_config;
  qsr_status_t status = qsr_config_load(runtime->config_path, &new_config);
  if (status != QSR_OK) {
    (void)fprintf(stderr, "reload: parse failed (%d) — keeping previous config\n", (int)status);
    return;
  }
  status = qsr_route_table_resolve(&new_config.routes);
  if (status != QSR_OK) {
    (void)fprintf(stderr, "reload: backend resolve failed (%d) — keeping previous config\n", (int)status);
    return;
  }
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

  /* Per-route diff lines are emitted before the atomic swap so the log
   * narrative reads "here's what's about to change, then ok". */
  log_route_diff(&runtime->config.routes, &new_config.routes);
  if (evicted > 0U) {
    (void)fprintf(stderr, "reload: %zu sessions evicted (backends removed)\n", evicted);
  }

  /* Atomic from the dataplane's point of view: we're single-threaded. */
  runtime->config.routes = new_config.routes;
  runtime->config.idle_timeout_seconds = new_config.idle_timeout_seconds;
  (void)fprintf(stderr, "reload: ok (%zu routes total)\n", runtime->config.routes.count);
}
#endif /* __linux__ */

qsr_status_t qsr_runtime_init(qsr_runtime_t *runtime, const qsr_config_t *config, const char *config_path) {
  if (runtime == nullptr || config == nullptr) {
    return QSR_ERR_INVALID;
  }
  runtime->config = *config;
  runtime->config_path = config_path;
  runtime->inotify_fd = -1;
  const qsr_status_t status = qsr_session_table_init(&runtime->sessions, runtime->config.max_sessions);
  if (status != QSR_OK) {
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
  if (runtime->inotify_fd >= 0) {
    (void)close(runtime->inotify_fd);
    runtime->inotify_fd = -1;
  }
#endif
  qsr_session_table_free(&runtime->sessions);
}

int qsr_runtime_inotify_fd(const qsr_runtime_t *runtime) {
  return runtime == nullptr ? -1 : runtime->inotify_fd;
}

/*
 * Conceptually a mutator (drives reload_from_path which writes runtime
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
  if (drain_inotify(runtime->inotify_fd)) {
    reload_from_path(runtime);
  }
#endif
}
