#include "qsr/udp.h"

#include "qsr/cid_codec.h"
#include "qsr/flow_table.h"
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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/resource.h>

#ifdef __linux__
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#else
#include <poll.h>
#include <sys/socket.h>
#endif

enum : int { QSR_EXPIRE_SWEEP_INTERVAL_SECONDS = 1 };
enum : unsigned { QSR_UDP_BATCH_SIZE = 64U };
/*
 * Per-recv-slot scratch buffer. Sized well above one Ethernet MTU so the
 * kernel can coalesce a burst from one peer tuple via UDP_GRO into a single
 * recvmmsg slot; the loop below splits the slot back into individual datagrams
 * via the SCM_UDP_GRO cmsg. Without GRO, only the first QSR_MAX_DATAGRAM_SIZE
 * bytes are used.
 */
enum : size_t { QSR_UDP_RECV_BUFFER_SIZE = 16U * 1024U };
enum : size_t { QSR_UDP_RECV_CMSG_SIZE = 64U };
enum : size_t { QSR_SESSION_EXPIRE_MIN_SCAN = 1024U };
enum : size_t { QSR_SESSION_EXPIRE_MAX_SCAN = 16384U };
enum : size_t { QSR_PENDING_INITIAL_CAPACITY = 64U };
enum : size_t { QSR_PENDING_INITIAL_MAX_PACKETS = 8U };
enum : time_t { QSR_PENDING_INITIAL_IDLE_SECONDS = 5 };
/* Non-flow fds need a few slots above the flow table: listen socket, epoll,
 * inotify, stdio, and the resolver's transient fds. */
enum : size_t { QSR_NOFILE_SLACK = 32U };

#ifdef __linux__
enum : int { QSR_EPOLL_MAX_EVENTS = 16 };
/* recvmmsg rounds per ready fd per wakeup. Level-triggered epoll re-reports
 * anything left, so this only bounds how long one fd can hog the loop. */
enum : unsigned { QSR_RECV_ROUNDS_PER_EVENT = 4U };
/* epoll user data: flow slot indices are < flow table capacity, so the top
 * two values are free to tag the non-flow fds. */
enum : uint64_t { QSR_EPOLL_DATA_MAIN = UINT64_MAX, QSR_EPOLL_DATA_INOTIFY = UINT64_MAX - 1U };
#endif

typedef struct qsr_udp_send_item {
  uint8_t packet[QSR_MAX_DATAGRAM_SIZE];
  size_t packet_len;
  struct sockaddr_storage dest;
  socklen_t dest_len;
  int fd;
} qsr_udp_send_item_t;

typedef struct qsr_udp_sender {
  qsr_udp_send_item_t items[QSR_UDP_BATCH_SIZE];
  size_t count;
} qsr_udp_sender_t;

typedef struct qsr_pending_initial {
  bool used;
  struct sockaddr_storage source;
  socklen_t source_len;
  uint8_t dcid[QSR_MAX_QUIC_CID_LEN];
  size_t dcid_len;
  uint8_t scid[QSR_MAX_QUIC_CID_LEN];
  size_t scid_len;
  qsr_session_key_t cid_key;
  qsr_crypto_stream_t crypto;
  uint8_t packets[QSR_PENDING_INITIAL_MAX_PACKETS][QSR_MAX_DATAGRAM_SIZE];
  size_t packet_lens[QSR_PENDING_INITIAL_MAX_PACKETS];
  size_t packet_count;
  time_t last_seen;
} qsr_pending_initial_t;

typedef struct qsr_pending_initial_table {
  qsr_pending_initial_t entries[QSR_PENDING_INITIAL_CAPACITY];
  size_t next_evict;
} qsr_pending_initial_table_t;

/*
 * Everything one packet-handling call needs. Bundled so the per-direction
 * handlers and the flow machinery don't grow six-argument tails.
 */
typedef struct qsr_dataplane {
  qsr_runtime_t *runtime;
  qsr_pending_initial_table_t *pending_initials;
  qsr_udp_sender_t sender;
  int main_fd;
  int epoll_fd; /* -1 on platforms without epoll */
} qsr_dataplane_t;

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

[[nodiscard]] static qsr_status_t set_nonblocking(int fd) {
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    return QSR_ERR_INVALID;
  }
  return QSR_OK;
}

/*
 * One fd per client flow means the default soft RLIMIT_NOFILE (often 1024)
 * is the first scaling wall. Raise it to the hard limit; warn if even that
 * cannot cover the flow table, so the operator learns at startup rather than
 * from EMFILE-driven evictions under load.
 */
static void raise_nofile_limit(size_t flow_capacity) {
  struct rlimit rl;
  if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
    return;
  }
  if (rl.rlim_cur < rl.rlim_max) {
    rl.rlim_cur = rl.rlim_max;
    (void)setrlimit(RLIMIT_NOFILE, &rl);
    (void)getrlimit(RLIMIT_NOFILE, &rl);
  }
  const unsigned long long limit = rl.rlim_cur;
  if (rl.rlim_cur != RLIM_INFINITY && limit < flow_capacity + QSR_NOFILE_SLACK) {
    (void)fprintf(stderr,
                  "quic-sni-router: RLIMIT_NOFILE %llu is below flow capacity %zu + %zu; concurrent connections "
                  "beyond the limit will evict the oldest flow (raise ulimit -n or lower sessions.maxSessions)\n",
                  limit, flow_capacity, QSR_NOFILE_SLACK);
  }
}

static void sender_init(qsr_udp_sender_t *sender) { memset(sender, 0, sizeof(*sender)); }

/*
 * Flush queued datagrams. Items are grouped into runs of consecutive equal
 * fds and each run goes out with one sendmmsg (Linux); a GRO burst from one
 * client therefore still leaves as a single batched syscall even though every
 * flow has its own upstream socket.
 */
static void sender_flush(qsr_udp_sender_t *sender) {
  if (sender->count == 0U) {
    return;
  }
#ifdef __linux__
  struct iovec iovecs[QSR_UDP_BATCH_SIZE] = {0};
  struct mmsghdr messages[QSR_UDP_BATCH_SIZE] = {0};
  size_t start = 0U;
  while (start < sender->count) {
    size_t end = start + 1U;
    while (end < sender->count && sender->items[end].fd == sender->items[start].fd) {
      end++;
    }
    for (size_t i = start; i < end; i++) {
      iovecs[i].iov_base = sender->items[i].packet;
      iovecs[i].iov_len = sender->items[i].packet_len;
      messages[i].msg_hdr.msg_iov = &iovecs[i];
      messages[i].msg_hdr.msg_iovlen = 1U;
      messages[i].msg_hdr.msg_name = &sender->items[i].dest;
      messages[i].msg_hdr.msg_namelen = sender->items[i].dest_len;
    }
    size_t sent = start;
    while (sent < end) {
      const int result = sendmmsg(sender->items[start].fd, &messages[sent], (unsigned int)(end - sent), MSG_DONTWAIT);
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
      if (result == 0) {
        break;
      }
      sent += (size_t)result;
    }
    start = end;
  }
#else
  for (size_t i = 0U; i < sender->count; i++) {
    (void)sendto(sender->items[i].fd, sender->items[i].packet, sender->items[i].packet_len, 0,
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
    sender_flush(sender);
  }
  qsr_udp_send_item_t *item = &sender->items[sender->count++];
  memcpy(item->packet, packet, packet_len);
  item->packet_len = packet_len;
  memcpy(&item->dest, dest, sizeof(*dest));
  item->dest_len = dest_len;
  item->fd = fd;
}

#ifdef QSR_ENABLE_PACKET_DEBUG
[[nodiscard]] static bool packet_debug_enabled(void) {
  static int cached = -1;
  if (cached < 0) {
    const char *value = getenv("QSR_DEBUG_PACKETS");
    cached = value != nullptr && value[0] != '\0' && strcmp(value, "0") != 0 ? 1 : 0;
  }
  return cached == 1;
}

static void format_addr(const struct sockaddr_storage *addr, socklen_t addr_len, char *out, size_t out_len) {
  char host[INET6_ADDRSTRLEN] = {0};
  uint16_t port;
  if (addr != nullptr && addr->ss_family == AF_INET && addr_len >= sizeof(struct sockaddr_in)) {
    const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
    (void)inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
    port = ntohs(sin->sin_port);
    (void)snprintf(out, out_len, "%s:%u", host, port);
  } else if (addr != nullptr && addr->ss_family == AF_INET6 && addr_len >= sizeof(struct sockaddr_in6)) {
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
    (void)inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
    port = ntohs(sin6->sin6_port);
    (void)snprintf(out, out_len, "[%s]:%u", host, port);
  } else {
    (void)snprintf(out, out_len, "?");
  }
}

[[nodiscard]] static const char *packet_kind(const uint8_t *packet, size_t packet_len) {
  if (packet_len == 0U) {
    return "empty";
  }
  if ((packet[0] & 0x80U) == 0U) {
    return (packet[0] & 0x40U) != 0U ? "short" : "short-no-fixed";
  }
  if ((packet[0] & 0x40U) == 0U) {
    return "long-no-fixed";
  }
  if (packet_len < 5U) {
    return "long-truncated";
  }
  const uint32_t version =
      ((uint32_t)packet[1] << 24U) | ((uint32_t)packet[2] << 16U) | ((uint32_t)packet[3] << 8U) | (uint32_t)packet[4];
  const uint8_t type_bits = packet[0] & 0x30U;
  if ((version == QSR_QUIC_V1 && type_bits == 0x00U) || (version == QSR_QUIC_V2 && type_bits == 0x10U)) {
    return "initial";
  }
  if ((version == QSR_QUIC_V1 && type_bits == 0x30U) || (version == QSR_QUIC_V2 && type_bits == 0x00U)) {
    return "retry";
  }
  if ((version == QSR_QUIC_V1 && type_bits == 0x20U) || (version == QSR_QUIC_V2 && type_bits == 0x30U)) {
    return "handshake";
  }
  return "long";
}

static void packet_debug_decision(const char *decision, const uint8_t *packet, size_t packet_len,
                                  const struct sockaddr_storage *source, socklen_t source_len,
                                  const struct sockaddr_storage *dest, socklen_t dest_len, bool source_is_backend,
                                  int status) {
  if (!packet_debug_enabled()) {
    return;
  }
  char src[INET6_ADDRSTRLEN + 16] = "?";
  char dst[INET6_ADDRSTRLEN + 16] = "?";
  format_addr(source, source_len, src, sizeof(src));
  if (dest != nullptr) {
    format_addr(dest, dest_len, dst, sizeof(dst));
  }
  (void)fprintf(stderr, "qsr packet decision=%s kind=%s len=%zu src=%s src_backend=%d dst=%s status=%d\n", decision,
                packet_kind(packet, packet_len), packet_len, src, source_is_backend ? 1 : 0, dst, status);
}

#define QSR_PACKET_DEBUG(...) packet_debug_decision(__VA_ARGS__)
#define QSR_PACKET_DECISION_VAR const char *packet_decision = "unclassified"
#define QSR_SET_PACKET_DECISION(value) (packet_decision = (value))
#define QSR_PACKET_DECISION packet_decision
#else
#define QSR_PACKET_DEBUG(...) ((void)0)
#define QSR_PACKET_DECISION_VAR ((void)0)
#define QSR_SET_PACKET_DECISION(value) ((void)0)
#define QSR_PACKET_DECISION "unclassified"
#endif

[[nodiscard]] static bool pending_initial_matches(const qsr_pending_initial_t *entry,
                                                  const struct sockaddr_storage *source, socklen_t source_len,
                                                  const qsr_quic_initial_t *initial) {
  return entry->used && entry->source_len == source_len && memcmp(&entry->source, source, source_len) == 0 &&
         entry->dcid_len == initial->dcid_len && entry->scid_len == initial->scid_len &&
         memcmp(entry->dcid, initial->dcid, initial->dcid_len) == 0 &&
         memcmp(entry->scid, initial->scid, initial->scid_len) == 0;
}

static qsr_pending_initial_t *pending_initial_get(qsr_pending_initial_table_t *table,
                                                  const struct sockaddr_storage *source, socklen_t source_len,
                                                  const qsr_quic_initial_t *initial, time_t now) {
  for (size_t i = 0U; i < QSR_PENDING_INITIAL_CAPACITY; i++) {
    if (pending_initial_matches(&table->entries[i], source, source_len, initial)) {
      table->entries[i].last_seen = now;
      return &table->entries[i];
    }
  }
  for (size_t i = 0U; i < QSR_PENDING_INITIAL_CAPACITY; i++) {
    if (!table->entries[i].used) {
      qsr_pending_initial_t *entry = &table->entries[i];
      memset(entry, 0, sizeof(*entry));
      entry->used = true;
      memcpy(&entry->source, source, sizeof(*source));
      entry->source_len = source_len;
      memcpy(entry->dcid, initial->dcid, initial->dcid_len);
      entry->dcid_len = initial->dcid_len;
      memcpy(entry->scid, initial->scid, initial->scid_len);
      entry->scid_len = initial->scid_len;
      entry->cid_key = qsr_session_cid_key(initial->dcid, initial->dcid_len, initial->scid, initial->scid_len);
      qsr_crypto_stream_init(&entry->crypto);
      entry->last_seen = now;
      return entry;
    }
  }

  qsr_pending_initial_t *entry = &table->entries[table->next_evict++ % QSR_PENDING_INITIAL_CAPACITY];
  memset(entry, 0, sizeof(*entry));
  entry->used = true;
  memcpy(&entry->source, source, sizeof(*source));
  entry->source_len = source_len;
  memcpy(entry->dcid, initial->dcid, initial->dcid_len);
  entry->dcid_len = initial->dcid_len;
  memcpy(entry->scid, initial->scid, initial->scid_len);
  entry->scid_len = initial->scid_len;
  entry->cid_key = qsr_session_cid_key(initial->dcid, initial->dcid_len, initial->scid, initial->scid_len);
  qsr_crypto_stream_init(&entry->crypto);
  entry->last_seen = now;
  return entry;
}

static void pending_initial_remove(qsr_pending_initial_table_t *table, const qsr_pending_initial_t *entry) {
  if (entry == nullptr) {
    return;
  }
  const size_t index = (size_t)(entry - table->entries);
  if (index < QSR_PENDING_INITIAL_CAPACITY) {
    memset(&table->entries[index], 0, sizeof(table->entries[index]));
  }
}

static void pending_initial_expire(qsr_pending_initial_table_t *table, time_t now) {
  for (size_t i = 0U; i < QSR_PENDING_INITIAL_CAPACITY; i++) {
    if (table->entries[i].used && now - table->entries[i].last_seen >= QSR_PENDING_INITIAL_IDLE_SECONDS) {
      memset(&table->entries[i], 0, sizeof(table->entries[i]));
    }
  }
}

static void pending_initial_append_packet(qsr_pending_initial_t *entry, const uint8_t *packet, size_t packet_len) {
  if (entry == nullptr || packet == nullptr || packet_len > QSR_MAX_DATAGRAM_SIZE) {
    return;
  }
  for (size_t i = 0U; i < entry->packet_count; i++) {
    if (entry->packet_lens[i] == packet_len && memcmp(entry->packets[i], packet, packet_len) == 0) {
      return;
    }
  }
  if (entry->packet_count >= QSR_PENDING_INITIAL_MAX_PACKETS) {
    return;
  }
  memcpy(entry->packets[entry->packet_count], packet, packet_len);
  entry->packet_lens[entry->packet_count] = packet_len;
  entry->packet_count++;
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

[[nodiscard]] static qsr_status_t route_crypto_stream(const qsr_config_t *config, const qsr_crypto_stream_t *crypto,
                                                      struct sockaddr_storage *backend, socklen_t *backend_len) {
  const size_t contiguous_len = qsr_crypto_stream_contiguous_len(crypto);
  if (contiguous_len == 0U) {
    return QSR_ERR_TRUNCATED;
  }

  qsr_sni_t sni;
  qsr_status_t status = qsr_tls_client_hello_sni(crypto->data, contiguous_len, &sni);
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

[[nodiscard]] static qsr_status_t
route_initial_datagram(const qsr_config_t *config, qsr_pending_initial_table_t *pending_initials, const uint8_t *packet,
                       size_t packet_len, const struct sockaddr_storage *source, socklen_t source_len, time_t now,
                       struct sockaddr_storage *backend, socklen_t *backend_len, qsr_session_key_t *cid_key,
                       qsr_pending_initial_t **pending_entry) {
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

  qsr_pending_initial_t *entry = pending_initial_get(pending_initials, source, source_len, &initial, now);
  pending_initial_append_packet(entry, packet, packet_len);
  qsr_crypto_stream_merge(&entry->crypto, &crypto);
  if (pending_entry != nullptr) {
    *pending_entry = entry;
  }
  if (cid_key != nullptr) {
    *cid_key = entry->cid_key;
  }
  return route_crypto_stream(config, &entry->crypto, backend, backend_len);
}

static void put_alias(qsr_session_table_t *sessions, const qsr_session_key_t *key, const struct sockaddr_storage *dest,
                      socklen_t dest_len, time_t now) {
  if (key->has_cids || key->has_tuple) {
    (void)qsr_session_table_put(sessions, key, dest, dest_len, now);
  }
}

/*
 * Learn forward-routing aliases from a client long-header packet: the DCID
 * (the server's CID once the handshake is underway, or the Retry SCID on a
 * post-Retry Initial) and the DCID+SCID pair both map to the backend, so
 * Initial retransmissions and NAT-rebound packets can be routed without
 * another ClientHello decrypt. The client's own SCID is deliberately NOT
 * aliased: backend return traffic arrives on per-flow sockets and never needs
 * a client-CID lookup, and storing it would only widen the false-match
 * surface of the short-header length scan.
 */
static void learn_client_long_header_cids(qsr_session_table_t *sessions, const uint8_t *packet, size_t packet_len,
                                          const struct sockaddr_storage *backend, socklen_t backend_len, time_t now) {
  /*
   * Hot-path short-circuit: this is called for every client packet of every
   * established session, and the vast majority are short-header 1-RTT
   * packets which can never contain learnable CIDs anyway. Peek the
   * long-header bit (and the fixed bit, which qsr_quic_parse_long_header would
   * also check) before paying the full parser invocation cost.
   */
  if (packet_len == 0U || (packet[0] & 0x80U) == 0U || (packet[0] & 0x40U) == 0U) {
    return;
  }
  qsr_quic_long_header_t header;
  if (qsr_quic_parse_long_header(packet, packet_len, &header) != QSR_OK) {
    return;
  }

  qsr_session_key_t dcid_key = qsr_session_single_cid_key(header.dcid, header.dcid_len);
  qsr_session_key_t pair_key = qsr_session_cid_key(header.dcid, header.dcid_len, header.scid, header.scid_len);
  put_alias(sessions, &dcid_key, backend, backend_len, now);
  put_alias(sessions, &pair_key, backend, backend_len, now);
}

/*
 * Learn the server-chosen SCID from a backend long-header packet (Initial,
 * Handshake, or Retry response) and alias it to the backend. A client's
 * subsequent packets carry that CID as their DCID, so this alias is what lets
 * short-header NAT rebinding and post-Retry Initials find the backend after
 * the client's tuple changed.
 */
static void learn_backend_scid(qsr_session_table_t *sessions, const uint8_t *packet, size_t packet_len,
                               const struct sockaddr_storage *backend, socklen_t backend_len, time_t now) {
  if (packet_len == 0U || (packet[0] & 0x80U) == 0U || (packet[0] & 0x40U) == 0U) {
    return;
  }
  qsr_quic_long_header_t header;
  if (qsr_quic_parse_long_header(packet, packet_len, &header) != QSR_OK) {
    return;
  }
  qsr_session_key_t scid_key = qsr_session_single_cid_key(header.scid, header.scid_len);
  put_alias(sessions, &scid_key, backend, backend_len, now);
}

[[nodiscard]] static qsr_session_t *lookup_long_header_request_dcid(const qsr_config_t *runtime_config,
                                                                    const qsr_session_table_t *sessions,
                                                                    const qsr_quic_initial_t *initial) {
  qsr_session_key_t dcid_key = qsr_session_single_cid_key(initial->dcid, initial->dcid_len);
  qsr_session_t *session = qsr_session_table_get(sessions, &dcid_key);
  if (session != nullptr &&
      qsr_route_table_has_backend(&runtime_config->routes, &session->backend_addr, session->backend_addr_len)) {
    return session;
  }
  return nullptr;
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
   * stale or attacker-planted aliases, both of which we close by refusing
   * the insert in the first place. Upper bound is the packet's available
   * bytes after the header byte, capped at 20 (QUIC v1 max).
   */
  const size_t max_cid_len = packet_len - 1U < QSR_MAX_QUIC_CID_LEN ? packet_len - 1U : QSR_MAX_QUIC_CID_LEN;
  const uint32_t learned_lengths = qsr_session_table_cid_len_mask(sessions);
  for (size_t cid_len = max_cid_len; cid_len >= QSR_MIN_LEARNED_CID_LEN; cid_len--) {
    if (learned_lengths != 0U && (learned_lengths & (1U << cid_len)) == 0U) {
      continue;
    }
    qsr_session_key_t key = qsr_session_single_cid_key(packet + 1U, cid_len);
    qsr_session_t *session = qsr_session_table_get(sessions, &key);
    if (session != nullptr) {
      return session;
    }
  }
  return nullptr;
}

[[nodiscard]] static qsr_session_t *lookup_long_header_dcid(const qsr_session_table_t *sessions, const uint8_t *packet,
                                                            size_t packet_len) {
  if (packet_len < 7U || (packet[0] & 0x80U) == 0U || (packet[0] & 0x40U) == 0U) {
    return nullptr;
  }
  const uint32_t version =
      ((uint32_t)packet[1] << 24U) | ((uint32_t)packet[2] << 16U) | ((uint32_t)packet[3] << 8U) | (uint32_t)packet[4];
  if (version != QSR_QUIC_V1 && version != QSR_QUIC_V2) {
    return nullptr;
  }
  const uint8_t dcid_len = packet[5];
  if (dcid_len < QSR_MIN_LEARNED_CID_LEN || dcid_len > QSR_MAX_QUIC_CID_LEN || 6U + (size_t)dcid_len >= packet_len) {
    return nullptr;
  }
  qsr_session_key_t dcid_key = qsr_session_single_cid_key(packet + 6U, dcid_len);
  return qsr_session_table_get(sessions, &dcid_key);
}

static void bind_client_tuple(qsr_session_table_t *sessions, const qsr_session_key_t *new_tuple_key,
                              const struct sockaddr_storage *backend, socklen_t backend_len, time_t now) {
  (void)qsr_session_table_put(sessions, new_tuple_key, backend, backend_len, now);
}

/*
 * Try to decode an encoded server_id out of the packet's destination CID.
 * Returns QSR_OK when the codec is enabled AND the DCID is a 16-byte encoded
 * CID that passes the magic check. Long headers carry an explicit DCID length;
 * short headers do not, so we read exactly QSR_CID_ENCODED_LEN bytes and let
 * the magic check reject everything else.
 */
[[nodiscard]] static qsr_status_t try_decode_dcid_server_id(const qsr_cid_codec_t *codec, const uint8_t *packet,
                                                            size_t packet_len, uint8_t *server_id) {
  if (codec == nullptr || !codec->enabled || packet == nullptr || packet_len < 1U) {
    return QSR_ERR_INVALID;
  }
  if ((packet[0] & 0x80U) != 0U) {
    /* Long header: DCID length is in byte 5; the layout sits after byte 0 +
     * 4 version bytes. */
    if ((packet[0] & 0x40U) == 0U || packet_len < 7U) {
      return QSR_ERR_INVALID;
    }
    const uint8_t dcid_len = packet[5];
    if (dcid_len != QSR_CID_ENCODED_LEN || 6U + (size_t)dcid_len > packet_len) {
      return QSR_ERR_INVALID;
    }
    return qsr_cid_codec_decode(codec, &packet[6], dcid_len, server_id);
  }
  /* Short header: no explicit DCID length. Try at the codec's fixed length;
   * the magic check rejects unrelated CIDs. */
  if ((packet[0] & 0x40U) == 0U || packet_len < 1U + QSR_CID_ENCODED_LEN) {
    return QSR_ERR_INVALID;
  }
  return qsr_cid_codec_decode(codec, &packet[1], QSR_CID_ENCODED_LEN, server_id);
}

/*
 * Route by encoded server_id. Returns the installed session, or nullptr if
 * the DCID does not decode or no resolved route matches.
 */
[[nodiscard]] static qsr_session_t *lookup_encoded_cid(const qsr_config_t *runtime_config,
                                                       qsr_session_table_t *sessions, const uint8_t *packet,
                                                       size_t packet_len, const qsr_session_key_t *tuple_key,
                                                       time_t now) {
  if (!runtime_config->cid_codec.enabled) {
    return nullptr;
  }
  uint8_t server_id = 0U;
  if (try_decode_dcid_server_id(&runtime_config->cid_codec, packet, packet_len, &server_id) != QSR_OK) {
    return nullptr;
  }
  const qsr_route_t *route = qsr_route_table_lookup_by_server_id(&runtime_config->routes, server_id);
  if (route == nullptr || !route->backend_resolved) {
    return nullptr;
  }
  bind_client_tuple(sessions, tuple_key, &route->backend_addr, route->backend_addr_len, now);
  return qsr_session_table_get(sessions, tuple_key);
}

static size_t session_expire_scan_budget(const qsr_session_table_t *sessions) {
  size_t budget = sessions->capacity / 60U;
  if (budget < QSR_SESSION_EXPIRE_MIN_SCAN) {
    budget = QSR_SESSION_EXPIRE_MIN_SCAN;
  }
  if (budget > QSR_SESSION_EXPIRE_MAX_SCAN) {
    budget = QSR_SESSION_EXPIRE_MAX_SCAN;
  }
  return budget;
}

static size_t flow_expire_scan_budget(const qsr_flow_table_t *flows) {
  size_t budget = flows->capacity / 60U;
  if (budget < QSR_SESSION_EXPIRE_MIN_SCAN) {
    budget = QSR_SESSION_EXPIRE_MIN_SCAN;
  }
  if (budget > QSR_SESSION_EXPIRE_MAX_SCAN) {
    budget = QSR_SESSION_EXPIRE_MAX_SCAN;
  }
  return budget;
}

/*
 * Open the upstream socket for one flow. On fd exhaustion the oldest flow is
 * evicted (closing its fd) and the open is retried once, so a flood of new
 * connections degrades to LRU flow recycling instead of hard failure.
 */
[[nodiscard]] static int flow_socket_open(qsr_flow_table_t *flows, sa_family_t family) {
  for (int attempt = 0; attempt < 2; attempt++) {
#ifdef __linux__
    const int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
#else
    const int fd = socket(family, SOCK_DGRAM, 0);
#endif
    if (fd >= 0) {
#ifndef __linux__
      if (set_nonblocking(fd) != QSR_OK) {
        (void)close(fd);
        return -1;
      }
      (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
#if defined(__linux__) && defined(UDP_GRO)
      /* Backend return traffic is the bulk direction; let the kernel coalesce
       * its bursts the same way the listen socket does. Best-effort. */
      int one = 1;
      (void)setsockopt(fd, IPPROTO_UDP, UDP_GRO, &one, sizeof(one));
#endif
      return fd;
    }
    if ((errno == EMFILE || errno == ENFILE) && attempt == 0 && qsr_flow_table_evict_oldest(flows) == 1U) {
      continue;
    }
    return -1;
  }
  return -1;
}

/*
 * Find or create the upstream flow for a client tuple. The flow's unconnected
 * socket gives this client a router source port of its own toward the backend,
 * which is what makes concurrent QUIC connections to one backend demux exactly
 * on the return path (the fd identifies the client; no CID inspection needed).
 */
[[nodiscard]] static qsr_flow_t *flow_acquire(qsr_dataplane_t *dp, const struct sockaddr_storage *client,
                                              socklen_t client_len, const struct sockaddr_storage *backend,
                                              socklen_t backend_len, time_t now) {
  qsr_flow_table_t *flows = &dp->runtime->flows;
  qsr_flow_t *flow = qsr_flow_table_get(flows, client, client_len);
  if (flow != nullptr) {
    if (flow->backend_addr_len != backend_len || memcmp(&flow->backend_addr, backend, backend_len) != 0) {
      /* Same client tuple, different backend: kernel source-port reuse after
       * a close, or a reload re-pointed the route. The socket is unconnected,
       * so re-aiming it is just a destination update. */
      memcpy(&flow->backend_addr, backend, sizeof(*backend));
      flow->backend_addr_len = backend_len;
    }
    flow->last_seen = now;
    return flow;
  }
  const int fd = flow_socket_open(flows, backend->ss_family);
  if (fd < 0) {
    return nullptr;
  }
  flow = qsr_flow_table_put(flows, client, client_len, backend, backend_len, fd, now);
  if (flow == nullptr) {
    (void)close(fd);
    return nullptr;
  }
#ifdef __linux__
  struct epoll_event event = {.events = EPOLLIN, .data.u64 = (uint64_t)qsr_flow_table_slot_of(flows, flow)};
  if (epoll_ctl(dp->epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
    qsr_flow_table_remove(flows, flow);
    return nullptr;
  }
#endif
  return flow;
}

/*
 * Client-to-backend path: every datagram arriving on the listen socket.
 * Backend traffic never lands here (backends answer the per-flow sockets), so
 * classification only has to find the right backend, then hand the datagram
 * to this client's flow.
 */
static void handle_client_packet(qsr_dataplane_t *dp, const uint8_t *packet, size_t packet_len,
                                 const struct sockaddr_storage *source, socklen_t source_len, time_t now) {
  const qsr_config_t *runtime_config = &dp->runtime->config;
  qsr_session_table_t *sessions = &dp->runtime->sessions;
  QSR_PACKET_DECISION_VAR;

  /*
   * Fast path: established short-header (1-RTT) traffic, the overwhelming
   * majority of packets on a busy router. The flow already pins this client
   * tuple to its backend, so the session table does not need to be consulted
   * at all; the flow lookup is the only hash probe on this path. Long-header
   * packets fall through: Initials must run the port-reuse-safe
   * classification, and other long headers want CID learning. Disabled when
   * encoded-CID routing is on, because that mode is contracted to route by
   * decoded server_id before any tuple state so active migration keeps
   * working (see docs/cid-routing.md).
   */
  if (!runtime_config->cid_codec.enabled && packet_len > 0U && (packet[0] & 0x80U) == 0U) {
    qsr_flow_t *fast_flow = qsr_flow_table_get(&dp->runtime->flows, source, source_len);
    if (fast_flow != nullptr) {
      fast_flow->last_seen = now;
      QSR_PACKET_DEBUG("flow_fast_path", packet, packet_len, source, source_len, &fast_flow->backend_addr,
                       fast_flow->backend_addr_len, false, 0);
      sender_enqueue(&dp->sender, fast_flow->fd, packet, packet_len, &fast_flow->backend_addr,
                     fast_flow->backend_addr_len);
      return;
    }
  }

  qsr_session_key_t key = qsr_session_tuple_key(source, source_len);
  qsr_session_t *session = nullptr;

  /*
   * Encoded-CID routing runs first when enabled. Any server-issued CID
   * decodes to the same server_id regardless of which CID the client picked
   * from its NEW_CONNECTION_ID pool, so this is the lookup that survives
   * active QUIC connection migration (RFC 9000 section 9), a path the
   * observed-CID heuristics below cannot follow because the post-handshake
   * NEW_CONNECTION_ID frames are encrypted in 1-RTT. Falls through to the
   * existing chain when the codec is disabled, the DCID is not encoded, or no
   * route matches the decoded server_id. See docs/cid-routing.md.
   */
  session = lookup_encoded_cid(runtime_config, sessions, packet, packet_len, &key, now);
  if (session != nullptr) {
    QSR_SET_PACKET_DECISION("encoded_cid");
  }

  /*
   * Initial packets bypass the tuple fast path. The trap is a kernel-reused
   * client source port: the stale tuple alias from a closed previous
   * connection still maps to a backend, so a bare tuple match would misroute
   * a fresh Initial. Retransmissions of an already-routed Initial are caught
   * by the DCID+SCID pair alias; post-Retry Initials (DCID = the backend's
   * Retry SCID, learned from the backend's response) by the DCID alias.
   * Anything else routes fresh by SNI below.
   */
  bool is_initial = false;
  {
    qsr_quic_initial_t initial;
    if (qsr_quic_parse_initial(packet, packet_len, &initial) == QSR_OK) {
      is_initial = true;
      qsr_session_key_t pair_key = qsr_session_cid_key(initial.dcid, initial.dcid_len, initial.scid, initial.scid_len);
      session = qsr_session_table_get(sessions, &pair_key);
      if (session != nullptr) {
        QSR_SET_PACKET_DECISION("initial_pair");
      }
      if (session == nullptr) {
        session = lookup_long_header_request_dcid(runtime_config, sessions, &initial);
        if (session != nullptr) {
          QSR_SET_PACKET_DECISION("initial_request_dcid");
        }
      }
    }
  }
  if (session == nullptr && !is_initial) {
    session = qsr_session_table_get(sessions, &key);
    if (session != nullptr) {
      QSR_SET_PACKET_DECISION("tuple");
    }
  }
  if (session == nullptr && !is_initial) {
    /*
     * NAT rebinding via short-header CID (the DCID is a server CID we learned
     * from the backend's long headers): install the new client tuple.
     */
    const qsr_session_t *cid_session = lookup_short_header_cid(sessions, packet, packet_len);
    if (cid_session != nullptr) {
      struct sockaddr_storage backend = cid_session->backend_addr;
      const socklen_t backend_len = cid_session->backend_addr_len;
      bind_client_tuple(sessions, &key, &backend, backend_len, now);
      session = qsr_session_table_get(sessions, &key);
      if (session != nullptr) {
        QSR_SET_PACKET_DECISION("short_cid_rebind");
      }
    }
  }
  if (session == nullptr && !is_initial) {
    /*
     * NAT rebinding via long-header DCID: a rebound Handshake or 0-RTT packet
     * carries a server CID as its DCID. Only honour aliases that point at a
     * configured backend; anything else would bounce a client's bytes toward
     * another client.
     */
    qsr_session_t *cid_session = lookup_long_header_dcid(sessions, packet, packet_len);
    if (cid_session != nullptr && qsr_route_table_has_backend(&runtime_config->routes, &cid_session->backend_addr,
                                                              cid_session->backend_addr_len)) {
      struct sockaddr_storage backend = cid_session->backend_addr;
      const socklen_t backend_len = cid_session->backend_addr_len;
      bind_client_tuple(sessions, &key, &backend, backend_len, now);
      session = qsr_session_table_get(sessions, &key);
      if (session != nullptr) {
        QSR_SET_PACKET_DECISION("long_dcid_rebind");
      }
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
      QSR_PACKET_DEBUG("drop_short_unknown", packet, packet_len, source, source_len, nullptr, 0, false, 0);
      return;
    }
    struct sockaddr_storage backend;
    socklen_t backend_len = 0;
    qsr_session_key_t cid_key;
    qsr_pending_initial_t *pending_entry = nullptr;
    qsr_status_t status = route_initial_datagram(runtime_config, dp->pending_initials, packet, packet_len, source,
                                                 source_len, now, &backend, &backend_len, &cid_key, &pending_entry);
    if (status != QSR_OK) {
      QSR_PACKET_DEBUG("buffer_initial", packet, packet_len, source, source_len, nullptr, 0, false, (int)status);
      return;
    }
    status = qsr_session_table_put(sessions, &key, &backend, backend_len, now);
    if (status != QSR_OK) {
      QSR_PACKET_DEBUG("drop_session_put", packet, packet_len, source, source_len, &backend, backend_len, false,
                       (int)status);
      return;
    }
    put_alias(sessions, &cid_key, &backend, backend_len, now);
    learn_client_long_header_cids(sessions, packet, packet_len, &backend, backend_len, now);
    qsr_flow_t *flow = flow_acquire(dp, source, source_len, &backend, backend_len, now);
    if (flow == nullptr) {
      QSR_PACKET_DEBUG("drop_no_flow", packet, packet_len, source, source_len, &backend, backend_len, false, 0);
      return;
    }
    /*
     * The triggering datagram was appended to the pending entry by
     * route_initial_datagram, so flushing the entry forwards it along with
     * any earlier fragments of a multi-datagram ClientHello.
     */
    if (pending_entry != nullptr) {
      for (size_t i = 0U; i < pending_entry->packet_count; i++) {
        QSR_PACKET_DEBUG("fresh_sni", pending_entry->packets[i], pending_entry->packet_lens[i], source, source_len,
                         &backend, backend_len, false, 0);
        sender_enqueue(&dp->sender, flow->fd, pending_entry->packets[i], pending_entry->packet_lens[i], &backend,
                       backend_len);
      }
      pending_initial_remove(dp->pending_initials, pending_entry);
    }
    return;
  }

  session->last_seen = now;
  qsr_flow_t *flow = flow_acquire(dp, source, source_len, &session->backend_addr, session->backend_addr_len, now);
  if (flow == nullptr) {
    QSR_PACKET_DEBUG("drop_no_flow", packet, packet_len, source, source_len, &session->backend_addr,
                     session->backend_addr_len, false, 0);
    return;
  }
  /*
   * Learning is cheap and idempotent: re-running here picks up CID rotations
   * on coalesced Initial+Handshake datagrams.
   */
  learn_client_long_header_cids(sessions, packet, packet_len, &session->backend_addr, session->backend_addr_len, now);
  QSR_PACKET_DEBUG(QSR_PACKET_DECISION, packet, packet_len, source, source_len, &session->backend_addr,
                   session->backend_addr_len, false, 0);
  sender_enqueue(&dp->sender, flow->fd, packet, packet_len, &session->backend_addr, session->backend_addr_len);
}

/*
 * Backend-to-client path: a datagram arriving on a flow's upstream socket.
 * The fd itself identifies the client, so this path does no session lookup at
 * all; it only learns the server's long-header SCID (for NAT-rebind recovery
 * on the client side) and relays the bytes from the listen socket so the
 * client keeps seeing the router's :443 tuple.
 */
static void handle_backend_packet(qsr_dataplane_t *dp, qsr_flow_t *flow, const uint8_t *packet, size_t packet_len,
                                  const struct sockaddr_storage *source, socklen_t source_len, time_t now) {
  flow->last_seen = now;
  learn_backend_scid(&dp->runtime->sessions, packet, packet_len, &flow->backend_addr, flow->backend_addr_len, now);
  QSR_PACKET_DEBUG("backend_flow", packet, packet_len, source, source_len, &flow->client_addr, flow->client_addr_len,
                   true, 0);
#ifndef QSR_ENABLE_PACKET_DEBUG
  (void)source;
  (void)source_len;
#endif
  sender_enqueue(&dp->sender, dp->main_fd, packet, packet_len, &flow->client_addr, flow->client_addr_len);
}

static void run_expiry_sweeps(qsr_dataplane_t *dp, time_t now) {
  qsr_runtime_t *runtime = dp->runtime;
  (void)qsr_session_table_expire_incremental(&runtime->sessions, now, (time_t)runtime->config.idle_timeout_seconds,
                                             session_expire_scan_budget(&runtime->sessions));
  (void)qsr_flow_table_expire_incremental(&runtime->flows, now, (time_t)runtime->config.idle_timeout_seconds,
                                          flow_expire_scan_budget(&runtime->flows));
  pending_initial_expire(dp->pending_initials, now);
}

#ifdef __linux__
[[nodiscard]] static qsr_status_t configure_socket(int fd, const struct addrinfo *ai) {
  int one = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
    return QSR_ERR_INVALID;
  }
  const int buffer_size = 4 * 1024 * 1024;
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
  (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
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
  /*
   * UDP_GRO asks the kernel to coalesce consecutive same-flow datagrams into
   * a single recvmmsg slot, returning the per-segment size via a SCM_UDP_GRO
   * ancillary message. Cuts per-packet recv overhead on bursty flows; we
   * demultiplex the buffer on receive. Best-effort: older kernels lack it.
   */
#ifdef UDP_GRO
  (void)setsockopt(fd, IPPROTO_UDP, UDP_GRO, &one, sizeof(one));
#endif
  return QSR_OK;
}

typedef struct qsr_recv_batch {
  uint8_t *recv_buffers;
  uint8_t *cmsg_buffers;
  struct sockaddr_storage *sources;
  struct iovec *iovecs;
  struct mmsghdr *messages;
} qsr_recv_batch_t;

static void recv_batch_free(qsr_recv_batch_t *batch) {
  free(batch->messages);
  free(batch->iovecs);
  free(batch->sources);
  free(batch->cmsg_buffers);
  free(batch->recv_buffers);
  memset(batch, 0, sizeof(*batch));
}

[[nodiscard]] static qsr_status_t recv_batch_init(qsr_recv_batch_t *batch) {
  /*
   * Heap-allocated so the receive buffers can be sized larger than one
   * Ethernet MTU to give UDP_GRO room to coalesce same-flow bursts; stack
   * allocation at QSR_UDP_BATCH_SIZE * QSR_UDP_RECV_BUFFER_SIZE = ~1 MiB
   * is too large to rely on across host environments.
   */
  batch->recv_buffers = calloc(QSR_UDP_BATCH_SIZE, QSR_UDP_RECV_BUFFER_SIZE);
  batch->cmsg_buffers = calloc(QSR_UDP_BATCH_SIZE, QSR_UDP_RECV_CMSG_SIZE);
  batch->sources = calloc(QSR_UDP_BATCH_SIZE, sizeof(*batch->sources));
  batch->iovecs = calloc(QSR_UDP_BATCH_SIZE, sizeof(*batch->iovecs));
  batch->messages = calloc(QSR_UDP_BATCH_SIZE, sizeof(*batch->messages));
  if (batch->recv_buffers == nullptr || batch->cmsg_buffers == nullptr || batch->sources == nullptr ||
      batch->iovecs == nullptr || batch->messages == nullptr) {
    recv_batch_free(batch);
    return QSR_ERR_FULL;
  }
  for (size_t i = 0U; i < QSR_UDP_BATCH_SIZE; i++) {
    batch->iovecs[i].iov_base = &batch->recv_buffers[i * QSR_UDP_RECV_BUFFER_SIZE];
    batch->iovecs[i].iov_len = QSR_UDP_RECV_BUFFER_SIZE;
    batch->messages[i].msg_hdr.msg_iov = &batch->iovecs[i];
    batch->messages[i].msg_hdr.msg_iovlen = 1U;
    batch->messages[i].msg_hdr.msg_name = &batch->sources[i];
    batch->messages[i].msg_hdr.msg_control = &batch->cmsg_buffers[i * QSR_UDP_RECV_CMSG_SIZE];
  }
  return QSR_OK;
}

/*
 * Drain one ready socket. `flow == nullptr` means the listen socket (client
 * direction); otherwise a flow's upstream socket (backend direction). Bounded
 * at QSR_RECV_ROUNDS_PER_EVENT batches; level-triggered epoll re-reports any
 * remainder, so a busy fd cannot starve the rest of the set.
 */
static void drain_socket(qsr_dataplane_t *dp, qsr_recv_batch_t *batch, int fd, qsr_flow_t *flow) {
  for (unsigned round = 0U; round < QSR_RECV_ROUNDS_PER_EVENT; round++) {
    for (size_t i = 0U; i < QSR_UDP_BATCH_SIZE; i++) {
      batch->messages[i].msg_len = 0U;
      batch->messages[i].msg_hdr.msg_namelen = sizeof(batch->sources[i]);
      batch->messages[i].msg_hdr.msg_controllen = QSR_UDP_RECV_CMSG_SIZE;
      batch->messages[i].msg_hdr.msg_flags = 0;
    }
    const int received_count = recvmmsg(fd, batch->messages, QSR_UDP_BATCH_SIZE, 0, nullptr);
    if (received_count < 0) {
      if (errno == EINTR) {
        continue;
      }
      return; /* EAGAIN: drained. Anything else: epoll will re-report or the fd is gone. */
    }
    const time_t now = monotonic_now();
    for (int i = 0; i < received_count; i++) {
      const size_t msg_len = batch->messages[i].msg_len;
      if (msg_len == 0U || msg_len > QSR_UDP_RECV_BUFFER_SIZE) {
        continue;
      }
      /*
       * The kernel sets MSG_TRUNC when a single datagram exceeded our receive
       * buffer. Splitting a truncated GRO burst would misalign the segments,
       * so drop the slot and rely on QUIC's loss recovery to retransmit.
       */
      if ((batch->messages[i].msg_hdr.msg_flags & MSG_TRUNC) != 0) {
        continue;
      }
      const uint8_t *slot = &batch->recv_buffers[(size_t)i * QSR_UDP_RECV_BUFFER_SIZE];
      size_t segment_size = msg_len;
#ifdef UDP_GRO
      for (struct cmsghdr *cm = CMSG_FIRSTHDR(&batch->messages[i].msg_hdr); cm != nullptr;
           cm = CMSG_NXTHDR(&batch->messages[i].msg_hdr, cm)) {
        if (cm->cmsg_level == SOL_UDP && cm->cmsg_type == UDP_GRO) {
          uint16_t gso = 0U;
          memcpy(&gso, CMSG_DATA(cm), sizeof(gso));
          if (gso > 0U) {
            segment_size = gso;
          }
          break;
        }
      }
#endif
      /* Whether GRO applied or not, a single segment must fit a UDP datagram. */
      if (segment_size > QSR_MAX_DATAGRAM_SIZE) {
        continue;
      }
      for (size_t offset = 0U; offset < msg_len;) {
        const size_t remaining = msg_len - offset;
        const size_t chunk = remaining < segment_size ? remaining : segment_size;
        if (flow == nullptr) {
          handle_client_packet(dp, slot + offset, chunk, &batch->sources[i], batch->messages[i].msg_hdr.msg_namelen,
                               now);
        } else {
          handle_backend_packet(dp, flow, slot + offset, chunk, &batch->sources[i],
                                batch->messages[i].msg_hdr.msg_namelen, now);
        }
        offset += chunk;
      }
    }
    if ((unsigned)received_count < QSR_UDP_BATCH_SIZE) {
      return;
    }
  }
}
#endif /* __linux__ */

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
  raise_nofile_limit(runtime.flows.capacity);

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

  if (set_nonblocking(fd) != QSR_OK) {
    (void)close(fd);
    qsr_runtime_free(&runtime);
    return QSR_ERR_INVALID;
  }

  qsr_pending_initial_table_t *pending_initials = calloc(1U, sizeof(*pending_initials));
  if (pending_initials == nullptr) {
    (void)close(fd);
    qsr_runtime_free(&runtime);
    return QSR_ERR_FULL;
  }

  qsr_dataplane_t dp = {
      .runtime = &runtime,
      .pending_initials = pending_initials,
      .main_fd = fd,
      .epoll_fd = -1,
  };
  sender_init(&dp.sender);

#ifdef __linux__
  int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (epoll_fd < 0) {
    free(pending_initials);
    (void)close(fd);
    qsr_runtime_free(&runtime);
    return QSR_ERR_INVALID;
  }
  dp.epoll_fd = epoll_fd;
  struct epoll_event event = {.events = EPOLLIN, .data.u64 = QSR_EPOLL_DATA_MAIN};
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
    (void)close(epoll_fd);
    free(pending_initials);
    (void)close(fd);
    qsr_runtime_free(&runtime);
    return QSR_ERR_INVALID;
  }
  /*
   * The runtime owns the inotify fd; we just register it with our epoll set
   * so blocking epoll_wait wakes for config-dir events as well as UDP traffic.
   * A negative fd (no path passed, or watch setup failed) just means hot
   * reload is disabled, not fatal. The event itself is only a wakeup; the
   * qsr_runtime_poll call at the top of the loop does the draining, so a
   * failed registration degrades to polling on traffic/timeout wakeups.
   */
  const int inotify_fd = qsr_runtime_inotify_fd(&runtime);
  if (inotify_fd >= 0) {
    struct epoll_event iev = {.events = EPOLLIN, .data.u64 = QSR_EPOLL_DATA_INOTIFY};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inotify_fd, &iev) < 0) {
      fprintf(stderr, "inotify epoll_ctl: %s\n", strerror(errno));
    }
  }
#endif

  fprintf(stderr, "quic-sni-router listening on udp %s with %zu route(s)\n", runtime.config.listen_udp,
          runtime.config.routes.count);
  qsr_runtime_log_routes("startup:", &runtime.config.routes);
#ifdef __linux__
  fprintf(stderr, "quic-sni-router dataplane: epoll + recvmmsg/sendmmsg, per-flow upstream sockets\n");
#else
  fprintf(stderr, "quic-sni-router dataplane: poll + recvfrom/sendto, per-flow upstream sockets\n");
#endif

  time_t last_expire = monotonic_now();

#ifdef __linux__
  qsr_recv_batch_t batch;
  if (recv_batch_init(&batch) != QSR_OK) {
    (void)close(epoll_fd);
    free(pending_initials);
    (void)close(fd);
    qsr_runtime_free(&runtime);
    return QSR_ERR_FULL;
  }

  while (!g_stop) {
    qsr_runtime_poll(&runtime);
    struct epoll_event events[QSR_EPOLL_MAX_EVENTS];
    const int ready = epoll_wait(epoll_fd, events, QSR_EPOLL_MAX_EVENTS, 1000);
    if (ready < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("epoll_wait");
      break;
    }
    for (int e = 0; e < ready; e++) {
      const uint64_t tag = events[e].data.u64;
      if (tag == QSR_EPOLL_DATA_MAIN) {
        drain_socket(&dp, &batch, fd, nullptr);
      } else if (tag == QSR_EPOLL_DATA_INOTIFY) {
        /* Wakeup only; the qsr_runtime_poll at the loop top drains it. */
      } else {
        /*
         * Re-resolve the slot at dispatch time: an earlier event in this
         * same batch may have evicted the flow (EMFILE recycling) or even
         * reused the slot for a new flow. Both are safe because we read the
         * slot's current state, not the state at epoll_wait time.
         */
        qsr_flow_t *flow = qsr_flow_table_slot(&runtime.flows, (size_t)tag);
        if (flow != nullptr) {
          drain_socket(&dp, &batch, flow->fd, flow);
        }
      }
    }
    sender_flush(&dp.sender);
    const time_t now = monotonic_now();
    if (now - last_expire >= QSR_EXPIRE_SWEEP_INTERVAL_SECONDS) {
      run_expiry_sweeps(&dp, now);
      last_expire = now;
    }
  }

  recv_batch_free(&batch);
  (void)close(epoll_fd);
#else
  /*
   * Portable fallback (macOS dev environments): poll() over the listen socket
   * plus every live flow socket. Rebuilding the pollfd array per iteration is
   * O(flow capacity), acceptable for a development path that is not expected
   * to carry production traffic.
   */
  struct pollfd *pfds = calloc(1U + runtime.flows.capacity, sizeof(*pfds));
  size_t *pfd_slots = calloc(runtime.flows.capacity, sizeof(*pfd_slots));
  if (pfds == nullptr || pfd_slots == nullptr) {
    free(pfd_slots);
    free(pfds);
    free(pending_initials);
    (void)close(fd);
    qsr_runtime_free(&runtime);
    return QSR_ERR_FULL;
  }

  while (!g_stop) {
    qsr_runtime_poll(&runtime);
    nfds_t nfds = 1;
    pfds[0].fd = fd;
    pfds[0].events = POLLIN;
    pfds[0].revents = 0;
    for (size_t slot = 0U; slot < runtime.flows.capacity; slot++) {
      const qsr_flow_t *flow = qsr_flow_table_slot(&runtime.flows, slot);
      if (flow != nullptr) {
        pfds[nfds].fd = flow->fd;
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        pfd_slots[nfds - 1U] = slot;
        nfds++;
      }
    }
    const int ready = poll(pfds, nfds, 1000);
    if (ready < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("poll");
      break;
    }
    const time_t now = monotonic_now();
    if ((pfds[0].revents & POLLIN) != 0) {
      for (unsigned i = 0U; i < QSR_UDP_BATCH_SIZE; i++) {
        uint8_t packet[QSR_MAX_DATAGRAM_SIZE];
        struct sockaddr_storage source = {0};
        socklen_t source_len = sizeof(source);
        const ssize_t received = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *)&source, &source_len);
        if (received <= 0) {
          break;
        }
        handle_client_packet(&dp, packet, (size_t)received, &source, source_len, now);
      }
    }
    for (nfds_t p = 1; p < nfds; p++) {
      if ((pfds[p].revents & POLLIN) == 0) {
        continue;
      }
      qsr_flow_t *flow = qsr_flow_table_slot(&runtime.flows, pfd_slots[p - 1U]);
      /* The flow may have been evicted (and its slot even reused) while
       * handling earlier fds in this pass; only drain if the fd still
       * belongs to the slot we polled. */
      if (flow == nullptr || flow->fd != pfds[p].fd) {
        continue;
      }
      for (unsigned i = 0U; i < QSR_UDP_BATCH_SIZE; i++) {
        uint8_t packet[QSR_MAX_DATAGRAM_SIZE];
        struct sockaddr_storage source = {0};
        socklen_t source_len = sizeof(source);
        const ssize_t received = recvfrom(flow->fd, packet, sizeof(packet), 0, (struct sockaddr *)&source, &source_len);
        if (received <= 0) {
          break;
        }
        handle_backend_packet(&dp, flow, packet, (size_t)received, &source, source_len, now);
      }
    }
    sender_flush(&dp.sender);
    if (now - last_expire >= QSR_EXPIRE_SWEEP_INTERVAL_SECONDS) {
      run_expiry_sweeps(&dp, now);
      last_expire = now;
    }
  }

  free(pfd_slots);
  free(pfds);
#endif

  sender_flush(&dp.sender);
  fprintf(stderr, "quic-sni-router: shutting down\n");
  free(pending_initials);
  qsr_runtime_free(&runtime);
  (void)close(fd);
  return QSR_OK;
}
