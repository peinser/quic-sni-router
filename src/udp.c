#include "qsr/udp.h"

#include "qsr/quic_crypto.h"
#include "qsr/quic_frames.h"
#include "qsr/quic_initial.h"
#include "qsr/runtime.h"
#include "qsr/session_table.h"
#include "qsr/tls_client_hello.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#endif

enum : int { QSR_EXPIRE_SWEEP_INTERVAL_SECONDS = 1 };
enum : unsigned { QSR_UDP_BATCH_SIZE = 32U };

typedef struct qsr_udp_send_item {
  uint8_t packet[QSR_MAX_DATAGRAM_SIZE];
  size_t packet_len;
  struct sockaddr_storage dest;
  socklen_t dest_len;
} qsr_udp_send_item_t;

typedef struct qsr_udp_sender {
  qsr_udp_send_item_t items[QSR_UDP_BATCH_SIZE];
  size_t count;
} qsr_udp_sender_t;

/*
 * Set by SIGINT/SIGTERM handler; the dataplane loop checks it between
 * batches so an operator can drain the process cleanly. Single global is
 * acceptable here because the dataplane is single-process.
 */
static volatile sig_atomic_t g_stop = 0;

static void handle_signal(int sig) {
  (void)sig;
  g_stop = 1;
}

static void install_signal_handlers(void) {
  struct sigaction sa = {.sa_handler = handle_signal};
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  (void)sigaction(SIGINT, &sa, nullptr);
  (void)sigaction(SIGTERM, &sa, nullptr);
  /*
   * Ignore SIGPIPE: a backend reset of an unrelated TCP connection on the
   * same process (e.g., DNS resolver bug) should not kill the dataplane.
   */
  struct sigaction sp = {.sa_handler = SIG_IGN};
  sigemptyset(&sp.sa_mask);
  (void)sigaction(SIGPIPE, &sp, nullptr);
}

static time_t monotonic_now(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    /* Fallback: wall clock. clock_gettime(CLOCK_MONOTONIC) never fails on Linux. */
    return time(nullptr);
  }
  return (time_t)ts.tv_sec;
}

static void sender_init(qsr_udp_sender_t *sender) { memset(sender, 0, sizeof(*sender)); }

static void sender_flush(qsr_udp_sender_t *sender, int fd) {
  if (sender->count == 0U) {
    return;
  }
#ifdef __linux__
  struct iovec iovecs[QSR_UDP_BATCH_SIZE] = {0};
  struct mmsghdr messages[QSR_UDP_BATCH_SIZE] = {0};
  for (size_t i = 0U; i < sender->count; i++) {
    iovecs[i].iov_base = sender->items[i].packet;
    iovecs[i].iov_len = sender->items[i].packet_len;
    messages[i].msg_hdr.msg_iov = &iovecs[i];
    messages[i].msg_hdr.msg_iovlen = 1U;
    messages[i].msg_hdr.msg_name = &sender->items[i].dest;
    messages[i].msg_hdr.msg_namelen = sender->items[i].dest_len;
  }
  size_t sent = 0U;
  while (sent < sender->count) {
    const int result = sendmmsg(fd, &messages[sent], (unsigned int)(sender->count - sent), 0);
    if (result < 0) {
      if (errno == EINTR) {
        continue;
      }
      /*
       * EAGAIN/ENOBUFS on a saturated send queue is best treated as a drop:
       * QUIC has its own loss recovery and retransmits.
       */
      break;
    }
    sent += (size_t)result;
  }
#else
  for (size_t i = 0U; i < sender->count; i++) {
    (void)sendto(fd, sender->items[i].packet, sender->items[i].packet_len, 0,
                 (const struct sockaddr *)&sender->items[i].dest, sender->items[i].dest_len);
  }
#endif
  sender->count = 0U;
}

static void sender_enqueue(qsr_udp_sender_t *sender, int fd, const uint8_t *packet, size_t packet_len,
                           const struct sockaddr_storage *dest, socklen_t dest_len) {
  if (packet_len > QSR_MAX_DATAGRAM_SIZE) {
    return;
  }
  if (sender->count >= QSR_UDP_BATCH_SIZE) {
    sender_flush(sender, fd);
  }
  qsr_udp_send_item_t *item = &sender->items[sender->count++];
  memcpy(item->packet, packet, packet_len);
  item->packet_len = packet_len;
  memcpy(&item->dest, dest, sizeof(*dest));
  item->dest_len = dest_len;
}

[[nodiscard]] static qsr_status_t split_listen(const char *listen, char *host, size_t host_len, char *port,
                                               size_t port_len) {
  const char *colon = strrchr(listen, ':');
  if (colon == nullptr) {
    return QSR_ERR_INVALID;
  }
  const size_t prefix_len = (size_t)(colon - listen);
  if (prefix_len >= host_len || strlen(colon + 1) >= port_len) {
    return QSR_ERR_INVALID;
  }
  if (prefix_len == 0U) {
    host[0] = '\0';
  } else {
    memcpy(host, listen, prefix_len);
    host[prefix_len] = '\0';
  }
  const size_t port_str_len = strlen(colon + 1);
  memcpy(port, colon + 1, port_str_len);
  port[port_str_len] = '\0';
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t route_initial_datagram(const qsr_config_t *config, const uint8_t *packet,
                                                         size_t packet_len, struct sockaddr_storage *backend,
                                                         socklen_t *backend_len, qsr_session_key_t *cid_key) {
  qsr_quic_initial_t initial;
  qsr_status_t status = qsr_quic_parse_initial(packet, packet_len, &initial);
  if (status != QSR_OK) {
    return status;
  }
  if (cid_key != nullptr) {
    *cid_key = qsr_session_cid_key(initial.dcid, initial.dcid_len, initial.scid, initial.scid_len);
  }

  qsr_quic_plaintext_t plaintext;
  status = qsr_quic_decrypt_initial(packet, packet_len, &initial, &plaintext);
  if (status != QSR_OK) {
    return status;
  }

  qsr_crypto_stream_t crypto;
  qsr_crypto_stream_init(&crypto);
  status = qsr_quic_extract_crypto(plaintext.data, plaintext.len, &crypto);
  if (status != QSR_OK) {
    return status;
  }

  qsr_sni_t sni;
  status = qsr_tls_client_hello_sni(crypto.data, crypto.len, &sni);
  if (status != QSR_OK) {
    return status;
  }

  const qsr_route_t *route = qsr_route_table_lookup(&config->routes, sni.name);
  if (route == nullptr) {
    return QSR_ERR_NOT_FOUND;
  }
  if (!route->backend_resolved) {
    return QSR_ERR_INVALID;
  }
  memcpy(backend, &route->backend_addr, sizeof(*backend));
  *backend_len = route->backend_addr_len;
  return QSR_OK;
}

static void put_alias(qsr_session_table_t *sessions, const qsr_session_key_t *key, const struct sockaddr_storage *dest,
                      socklen_t dest_len, time_t now) {
  if (key->has_cids || key->has_tuple) {
    (void)qsr_session_table_put(sessions, key, dest, dest_len, now);
  }
}

static void learn_long_header_cids(qsr_session_table_t *sessions, const uint8_t *packet, size_t packet_len,
                                   const struct sockaddr_storage *source, socklen_t source_len,
                                   const struct sockaddr_storage *dest, socklen_t dest_len, time_t now) {
  /*
   * Hot-path short-circuit: this is called for every packet of every
   * established session, and the vast majority are short-header 1-RTT
   * packets which can never contain learnable CIDs anyway. Peek the
   * long-header bit (and the fixed bit, which qsr_quic_parse_initial would
   * also check) before paying the full parser invocation cost.
   */
  if (packet_len == 0U || (packet[0] & 0x80U) == 0U || (packet[0] & 0x40U) == 0U) {
    return;
  }
  qsr_quic_initial_t initial;
  if (qsr_quic_parse_initial(packet, packet_len, &initial) != QSR_OK) {
    return;
  }

  qsr_session_key_t dcid_key = qsr_session_single_cid_key(initial.dcid, initial.dcid_len);
  qsr_session_key_t scid_key = qsr_session_single_cid_key(initial.scid, initial.scid_len);
  qsr_session_key_t pair_key = qsr_session_cid_key(initial.dcid, initial.dcid_len, initial.scid, initial.scid_len);
  put_alias(sessions, &dcid_key, dest, dest_len, now);
  put_alias(sessions, &scid_key, source, source_len, now);
  put_alias(sessions, &pair_key, dest, dest_len, now);
}

[[nodiscard]] static qsr_session_t *lookup_short_header_cid(const qsr_session_table_t *sessions, const uint8_t *packet,
                                                            size_t packet_len) {
  if (packet_len < 1U + QSR_MIN_LEARNED_CID_LEN || (packet[0] & 0x80U) != 0U || (packet[0] & 0x40U) == 0U) {
    return nullptr;
  }
  /*
   * Iterate from longest to shortest. The lower bound is QSR_MIN_LEARNED_CID_LEN
   * because qsr_session_single_cid_key rejects anything below that floor at
   * insertion time, so iterating shorter lengths can only false-match against
   * stale or attacker-planted aliases — both of which we close by refusing
   * the insert in the first place. Upper bound is the packet's available
   * bytes after the header byte, capped at 20 (QUIC v1 max).
   */
  const size_t max_cid_len = packet_len - 1U < QSR_MAX_QUIC_CID_LEN ? packet_len - 1U : QSR_MAX_QUIC_CID_LEN;
  for (size_t cid_len = max_cid_len; cid_len >= QSR_MIN_LEARNED_CID_LEN; cid_len--) {
    qsr_session_key_t key = qsr_session_single_cid_key(packet + 1U, cid_len);
    qsr_session_t *session = qsr_session_table_get(sessions, &key);
    if (session != nullptr) {
      return session;
    }
  }
  return nullptr;
}

[[nodiscard]] static qsr_session_t *lookup_rebound_initial(const qsr_session_table_t *sessions, const uint8_t *packet,
                                                           size_t packet_len, qsr_session_key_t *cid_key) {
  /* Same short-circuit as learn_long_header_cids: only long-header packets
   * can be Initials. Saves the parser invocation for the common case where a
   * source without a tuple match is sending a 1-RTT short-header packet. */
  if (packet_len == 0U || (packet[0] & 0x80U) == 0U || (packet[0] & 0x40U) == 0U) {
    return nullptr;
  }
  qsr_quic_initial_t initial;
  if (qsr_quic_parse_initial(packet, packet_len, &initial) != QSR_OK) {
    return nullptr;
  }
  *cid_key = qsr_session_cid_key(initial.dcid, initial.dcid_len, initial.scid, initial.scid_len);
  return qsr_session_table_get(sessions, cid_key);
}

#ifdef __linux__
[[nodiscard]] static qsr_status_t set_nonblocking(int fd) {
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    return QSR_ERR_INVALID;
  }
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t wait_readable(int epoll_fd) {
  struct epoll_event event = {0};
  for (;;) {
    if (g_stop) {
      return QSR_ERR_INVALID;
    }
    const int ready = epoll_wait(epoll_fd, &event, 1, 1000);
    if (ready > 0 || ready == 0) {
      return QSR_OK;
    }
    if (errno == EINTR) {
      continue;
    }
    return QSR_ERR_INVALID;
  }
}
#endif

static void rebind_session(qsr_session_table_t *sessions, const qsr_session_key_t *new_tuple_key,
                           const struct sockaddr_storage *new_source, socklen_t new_source_len,
                           const struct sockaddr_storage *backend, socklen_t backend_len, time_t now) {
  (void)qsr_session_table_put(sessions, new_tuple_key, backend, backend_len, now);
  qsr_session_key_t reverse_key = qsr_session_tuple_key(backend, backend_len);
  (void)qsr_session_table_put(sessions, &reverse_key, new_source, new_source_len, now);
}

static void handle_packet(const qsr_config_t *runtime_config, qsr_session_table_t *sessions, qsr_udp_sender_t *sender,
                          int fd, const uint8_t *packet, size_t packet_len, const struct sockaddr_storage *source,
                          socklen_t source_len, time_t now) {
  qsr_session_key_t key = qsr_session_tuple_key(source, source_len);
  qsr_session_t *session = qsr_session_table_get(sessions, &key);
  if (session == nullptr) {
    const qsr_session_t *cid_session = lookup_short_header_cid(sessions, packet, packet_len);
    if (cid_session != nullptr) {
      /*
       * NAT rebinding via short-header CID: install both directions of the new
       * tuple so backend replies follow the client. The previous implementation
       * forgot the reverse alias and silently black-holed reply traffic.
       */
      struct sockaddr_storage backend = cid_session->backend_addr;
      const socklen_t backend_len = cid_session->backend_addr_len;
      rebind_session(sessions, &key, source, source_len, &backend, backend_len, now);
      session = qsr_session_table_get(sessions, &key);
    }
  }
  if (session == nullptr) {
    qsr_session_key_t cid_key;
    const qsr_session_t *cid_session = lookup_rebound_initial(sessions, packet, packet_len, &cid_key);
    if (cid_session != nullptr) {
      struct sockaddr_storage backend = cid_session->backend_addr;
      const socklen_t backend_len = cid_session->backend_addr_len;
      rebind_session(sessions, &key, source, source_len, &backend, backend_len, now);
      session = qsr_session_table_get(sessions, &key);
    }
  }
  if (session == nullptr) {
    /*
     * Anti-amplification floor (RFC 9000 14.1): real clients pad Initial
     * datagrams to >= 1200 bytes. Anything shorter from an unknown source
     * is either a probe, a spoofed reflection attempt, or a non-Initial
     * packet for a session we don't have. Drop without doing any crypto so
     * an attacker cannot burn CPU on us for free.
     */
    if (packet_len < QSR_MIN_INITIAL_DATAGRAM_SIZE) {
      return;
    }
    struct sockaddr_storage backend;
    socklen_t backend_len = 0;
    qsr_session_key_t cid_key;
    qsr_status_t status = route_initial_datagram(runtime_config, packet, packet_len, &backend, &backend_len, &cid_key);
    if (status != QSR_OK) {
      return;
    }
    status = qsr_session_table_put(sessions, &key, &backend, backend_len, now);
    if (status != QSR_OK) {
      return;
    }
    put_alias(sessions, &cid_key, &backend, backend_len, now);
    learn_long_header_cids(sessions, packet, packet_len, source, source_len, &backend, backend_len, now);
    qsr_session_key_t reverse_key = qsr_session_tuple_key(&backend, backend_len);
    (void)qsr_session_table_put(sessions, &reverse_key, source, source_len, now);
    session = qsr_session_table_get(sessions, &key);
    if (session == nullptr) {
      return;
    }
  }

  session->last_seen = now;
  /*
   * Learning is cheap and idempotent: re-running here picks up CID rotations
   * on coalesced Initial+Handshake datagrams from either direction.
   */
  learn_long_header_cids(sessions, packet, packet_len, source, source_len, &session->backend_addr,
                         session->backend_addr_len, now);
  sender_enqueue(sender, fd, packet, packet_len, &session->backend_addr, session->backend_addr_len);
}

#ifdef __linux__
[[nodiscard]] static qsr_status_t configure_socket(int fd, const struct addrinfo *ai) {
  int one = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
    return QSR_ERR_INVALID;
  }
  /*
   * SO_REUSEPORT lets an operator scale by launching multiple router processes
   * bound to the same UDP port; the kernel hashes incoming flows across them.
   * Without this, the dataplane is capped to a single core.
   *
   * Not fatal if unavailable (older kernels): warn and continue.
   */
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
    fprintf(stderr, "quic-sni-router: SO_REUSEPORT unavailable: %s\n", strerror(errno));
  }
  if (ai->ai_family == AF_INET6) {
    int zero = 0;
    /*
     * Allow the IPv6 listener to receive IPv4-mapped traffic as well; without
     * this, an IPv6 bind only handles v6. Best-effort.
     */
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
  }
  return QSR_OK;
}
#endif

qsr_status_t qsr_udp_run(const qsr_config_t *config, const char *config_path) {
  if (config == nullptr) {
    return QSR_ERR_INVALID;
  }

  install_signal_handlers();

  qsr_runtime_t runtime;
  qsr_status_t status = qsr_runtime_init(&runtime, config, config_path);
  if (status != QSR_OK) {
    return status;
  }
  status = qsr_route_table_resolve(&runtime.config.routes);
  if (status != QSR_OK) {
    fprintf(stderr, "failed to resolve configured route backend\n");
    qsr_runtime_free(&runtime);
    return status;
  }

  char host[64] = {0};
  char port[16] = {0};
  status = split_listen(runtime.config.listen_udp, host, sizeof(host), port, sizeof(port));
  if (status != QSR_OK) {
    qsr_runtime_free(&runtime);
    return status;
  }

  struct addrinfo hints = {
      .ai_family = AF_UNSPEC,
      .ai_socktype = SOCK_DGRAM,
      .ai_flags = AI_PASSIVE | AI_NUMERICSERV,
  };

  struct addrinfo *res = nullptr;
  const int gai = getaddrinfo(host[0] == '\0' ? nullptr : host, port, &hints, &res);
  if (gai != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
    qsr_runtime_free(&runtime);
    return QSR_ERR_INVALID;
  }

  int fd = -1;
  for (const struct addrinfo *ai = res; ai != nullptr; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
    if (fd < 0) {
      continue;
    }
#ifdef __linux__
    if (configure_socket(fd, ai) != QSR_OK) {
      (void)close(fd);
      fd = -1;
      continue;
    }
#else
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif
    if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
      break;
    }
    (void)close(fd);
    fd = -1;
  }
  freeaddrinfo(res);

  if (fd < 0) {
    perror("bind");
    qsr_runtime_free(&runtime);
    return QSR_ERR_INVALID;
  }

#ifdef __linux__
  if (set_nonblocking(fd) != QSR_OK) {
    (void)close(fd);
    qsr_runtime_free(&runtime);
    return QSR_ERR_INVALID;
  }
  int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (epoll_fd < 0) {
    (void)close(fd);
    qsr_runtime_free(&runtime);
    return QSR_ERR_INVALID;
  }
  struct epoll_event event = {.events = EPOLLIN, .data.fd = fd};
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
    (void)close(epoll_fd);
    (void)close(fd);
    qsr_runtime_free(&runtime);
    return QSR_ERR_INVALID;
  }
  /*
   * The runtime owns the inotify fd; we just register it with our epoll set
   * so blocking epoll_wait wakes for config-dir events as well as UDP traffic.
   * A negative fd (no path passed, or watch setup failed) just means hot
   * reload is disabled — not fatal.
   */
  const int inotify_fd = qsr_runtime_inotify_fd(&runtime);
  if (inotify_fd >= 0) {
    struct epoll_event iev = {.events = EPOLLIN, .data.fd = inotify_fd};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inotify_fd, &iev) < 0) {
      fprintf(stderr, "inotify epoll_ctl: %s\n", strerror(errno));
    }
  }
#endif

  fprintf(stderr, "quic-sni-router listening on udp %s with %zu route(s)\n", runtime.config.listen_udp,
          runtime.config.routes.count);
  qsr_runtime_log_routes("startup:", &runtime.config.routes);
#ifdef __linux__
  fprintf(stderr, "quic-sni-router dataplane: epoll + recvmmsg/sendmmsg\n");
#else
  fprintf(stderr, "quic-sni-router dataplane: recvfrom/sendto\n");
#endif

  time_t last_expire = monotonic_now();
  qsr_udp_sender_t sender;
  sender_init(&sender);
  while (!g_stop) {
#ifdef __linux__
    qsr_runtime_poll(&runtime);
    uint8_t packets[QSR_UDP_BATCH_SIZE][QSR_MAX_DATAGRAM_SIZE];
    struct sockaddr_storage sources[QSR_UDP_BATCH_SIZE] = {0};
    struct iovec iovecs[QSR_UDP_BATCH_SIZE] = {0};
    struct mmsghdr messages[QSR_UDP_BATCH_SIZE] = {0};
    for (size_t i = 0U; i < QSR_UDP_BATCH_SIZE; i++) {
      iovecs[i].iov_base = packets[i];
      iovecs[i].iov_len = sizeof(packets[i]);
      messages[i].msg_hdr.msg_iov = &iovecs[i];
      messages[i].msg_hdr.msg_iovlen = 1U;
      messages[i].msg_hdr.msg_name = &sources[i];
      messages[i].msg_hdr.msg_namelen = sizeof(sources[i]);
    }

    int received_count = recvmmsg(fd, messages, QSR_UDP_BATCH_SIZE, 0, nullptr);
    if (received_count < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        if (wait_readable(epoll_fd) != QSR_OK) {
          break;
        }
        const time_t sweep_now = monotonic_now();
        if (sweep_now - last_expire >= QSR_EXPIRE_SWEEP_INTERVAL_SECONDS) {
          (void)qsr_session_table_expire(&runtime.sessions, sweep_now,
                                         (time_t)runtime.config.idle_timeout_seconds);
          last_expire = sweep_now;
        }
        continue;
      }
      perror("recvmmsg");
      break;
    }
    const time_t now = monotonic_now();
    for (int i = 0; i < received_count; i++) {
      if (messages[i].msg_len == 0U || messages[i].msg_len > QSR_MAX_DATAGRAM_SIZE) {
        continue;
      }
      handle_packet(&runtime.config, &runtime.sessions, &sender, fd, packets[i], messages[i].msg_len, &sources[i],
                    messages[i].msg_hdr.msg_namelen, now);
    }
    sender_flush(&sender, fd);
#else
    uint8_t packet[QSR_MAX_DATAGRAM_SIZE];
    struct sockaddr_storage source = {0};
    socklen_t source_len = sizeof(source);
    const ssize_t received = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *)&source, &source_len);
    if (received < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("recvfrom");
      break;
    }
    if (received == 0 || (size_t)received > QSR_MAX_DATAGRAM_SIZE) {
      continue;
    }

    const time_t now = monotonic_now();
    handle_packet(&runtime.config, &runtime.sessions, &sender, fd, packet, (size_t)received, &source, source_len, now);
    sender_flush(&sender, fd);
#endif
    if (now - last_expire >= QSR_EXPIRE_SWEEP_INTERVAL_SECONDS) {
      (void)qsr_session_table_expire(&runtime.sessions, now, (time_t)runtime.config.idle_timeout_seconds);
      last_expire = now;
    }
  }

  sender_flush(&sender, fd);
  fprintf(stderr, "quic-sni-router: shutting down\n");
  qsr_runtime_free(&runtime);
#ifdef __linux__
  (void)close(epoll_fd);
#endif
  (void)close(fd);
  return QSR_OK;
}
