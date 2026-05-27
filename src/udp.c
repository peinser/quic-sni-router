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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

#ifdef __linux__
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#endif

enum : int { QSR_EXPIRE_SWEEP_INTERVAL_SECONDS = 1 };
enum : unsigned { QSR_UDP_BATCH_SIZE = 32U };
enum : size_t { QSR_SESSION_EXPIRE_MIN_SCAN = 1024U };
enum : size_t { QSR_SESSION_EXPIRE_MAX_SCAN = 16384U };
enum : size_t { QSR_PENDING_INITIAL_CAPACITY = 64U };
enum : size_t { QSR_PENDING_INITIAL_MAX_PACKETS = 8U };
enum : time_t { QSR_PENDING_INITIAL_IDLE_SECONDS = 5 };

#ifdef __linux__
enum : unsigned { QSR_URING_RECV_BUFFERS = 128U };
enum : unsigned { QSR_URING_RECV_BGID = 7U };
enum : uint64_t { QSR_URING_MULTISHOT_USER_DATA = UINT64_MAX };
enum : size_t {
  QSR_URING_RECV_BUFFER_SIZE =
      sizeof(struct io_uring_recvmsg_out) + sizeof(struct sockaddr_storage) + QSR_MAX_DATAGRAM_SIZE
};
#endif

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

#ifdef __linux__
typedef struct qsr_uring {
  int fd;
  bool recv_poll_first;
  struct io_uring_buf_ring *recv_buf_ring;
  size_t recv_buf_ring_sz;
  uint8_t *recv_buffers;
  uint16_t recv_buf_tail;
  void *sq_ring;
  size_t sq_ring_sz;
  void *cq_ring;
  size_t cq_ring_sz;
  struct io_uring_sqe *sqes;
  size_t sqes_sz;
  unsigned *sq_head;
  unsigned *sq_tail;
  unsigned *sq_ring_mask;
  unsigned *sq_ring_entries;
  unsigned *sq_array;
  unsigned *cq_head;
  unsigned *cq_tail;
  unsigned *cq_ring_mask;
  struct io_uring_cqe *cqes;
} qsr_uring_t;

static int qsr_io_uring_setup(unsigned entries, struct io_uring_params *params) {
  return (int)syscall(__NR_io_uring_setup, entries, params);
}

static int qsr_io_uring_enter(int ring_fd, unsigned to_submit, unsigned min_complete, unsigned flags) {
  return (int)syscall(__NR_io_uring_enter, ring_fd, to_submit, min_complete, flags, nullptr, 0U);
}

static int qsr_io_uring_register(int ring_fd, unsigned opcode, const void *arg, unsigned nr_args) {
  return (int)syscall(__NR_io_uring_register, ring_fd, opcode, arg, nr_args);
}

static void qsr_uring_close(qsr_uring_t *ring) {
  if (ring == nullptr) {
    return;
  }
  if (ring->fd >= 0 && ring->recv_buf_ring != nullptr) {
    const struct io_uring_buf_reg reg = {.bgid = QSR_URING_RECV_BGID};
    (void)qsr_io_uring_register(ring->fd, IORING_UNREGISTER_PBUF_RING, &reg, 1U);
  }
  if (ring->recv_buf_ring != MAP_FAILED && ring->recv_buf_ring != nullptr) {
    (void)munmap(ring->recv_buf_ring, ring->recv_buf_ring_sz);
  }
  free(ring->recv_buffers);
  if (ring->sqes != MAP_FAILED && ring->sqes != nullptr) {
    (void)munmap(ring->sqes, ring->sqes_sz);
  }
  if (ring->cq_ring != MAP_FAILED && ring->cq_ring != nullptr && ring->cq_ring != ring->sq_ring) {
    (void)munmap(ring->cq_ring, ring->cq_ring_sz);
  }
  if (ring->sq_ring != MAP_FAILED && ring->sq_ring != nullptr) {
    (void)munmap(ring->sq_ring, ring->sq_ring_sz);
  }
  if (ring->fd >= 0) {
    (void)close(ring->fd);
  }
  memset(ring, 0, sizeof(*ring));
  ring->fd = -1;
}

static void qsr_uring_buf_ring_add(qsr_uring_t *ring, uint16_t bid, uint16_t offset) {
  struct io_uring_buf *buf = &ring->recv_buf_ring->bufs[(ring->recv_buf_tail + offset) & (QSR_URING_RECV_BUFFERS - 1U)];
  buf->addr = (uint64_t)(uintptr_t)&ring->recv_buffers[(size_t)bid * QSR_URING_RECV_BUFFER_SIZE];
  buf->len = QSR_URING_RECV_BUFFER_SIZE;
  buf->bid = bid;
  buf->resv = 0;
}

static void qsr_uring_buf_ring_advance(qsr_uring_t *ring, uint16_t count) {
  ring->recv_buf_tail = (uint16_t)(ring->recv_buf_tail + count);
  __atomic_store_n(&ring->recv_buf_ring->tail, ring->recv_buf_tail, __ATOMIC_RELEASE);
}

[[nodiscard]] static qsr_status_t qsr_uring_register_recv_buffers(qsr_uring_t *ring) {
  if (ring == nullptr || ring->fd < 0) {
    return QSR_ERR_INVALID;
  }
  ring->recv_buffers = calloc(QSR_URING_RECV_BUFFERS, QSR_URING_RECV_BUFFER_SIZE);
  if (ring->recv_buffers == nullptr) {
    return QSR_ERR_FULL;
  }

  struct io_uring_buf_reg reg = {
      .ring_entries = QSR_URING_RECV_BUFFERS,
      .bgid = QSR_URING_RECV_BGID,
      .flags = IOU_PBUF_RING_MMAP,
  };
  if (qsr_io_uring_register(ring->fd, IORING_REGISTER_PBUF_RING, &reg, 1U) < 0) {
    free(ring->recv_buffers);
    ring->recv_buffers = nullptr;
    return QSR_ERR_UNSUPPORTED;
  }

  ring->recv_buf_ring_sz = (size_t)QSR_URING_RECV_BUFFERS * sizeof(struct io_uring_buf);
  ring->recv_buf_ring = mmap(nullptr, ring->recv_buf_ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                             ring->fd, IORING_OFF_PBUF_RING | (QSR_URING_RECV_BGID << IORING_OFF_PBUF_SHIFT));
  if (ring->recv_buf_ring == MAP_FAILED) {
    const struct io_uring_buf_reg unregister_reg = {.bgid = QSR_URING_RECV_BGID};
    (void)qsr_io_uring_register(ring->fd, IORING_UNREGISTER_PBUF_RING, &unregister_reg, 1U);
    free(ring->recv_buffers);
    ring->recv_buffers = nullptr;
    ring->recv_buf_ring = nullptr;
    return QSR_ERR_UNSUPPORTED;
  }

  ring->recv_buf_tail = 0;
  for (size_t i = 0U; i < QSR_URING_RECV_BUFFERS; i++) {
    qsr_uring_buf_ring_add(ring, (uint16_t)i, (uint16_t)i);
  }
  qsr_uring_buf_ring_advance(ring, QSR_URING_RECV_BUFFERS);
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t qsr_uring_recvmsg_multishot(qsr_uring_t *ring, int fd, struct msghdr *message) {
  const unsigned head = __atomic_load_n(ring->sq_head, __ATOMIC_ACQUIRE);
  const unsigned tail = __atomic_load_n(ring->sq_tail, __ATOMIC_RELAXED);
  if (tail - head >= *ring->sq_ring_entries) {
    return QSR_ERR_FULL;
  }
  const unsigned index = tail & *ring->sq_ring_mask;
  struct io_uring_sqe *sqe = &ring->sqes[index];
  memset(sqe, 0, sizeof(*sqe));
  sqe->opcode = IORING_OP_RECVMSG;
  sqe->flags = IOSQE_BUFFER_SELECT;
  sqe->ioprio = IORING_RECV_MULTISHOT;
  if (ring->recv_poll_first) {
    sqe->ioprio |= IORING_RECVSEND_POLL_FIRST;
  }
  sqe->fd = fd;
  sqe->addr = (uint64_t)(uintptr_t)message;
  sqe->len = 1U;
  sqe->msg_flags = 0U;
  sqe->user_data = QSR_URING_MULTISHOT_USER_DATA;
  sqe->buf_group = QSR_URING_RECV_BGID;
  ring->sq_array[index] = index;
  __atomic_store_n(ring->sq_tail, tail + 1U, __ATOMIC_RELEASE);
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t qsr_uring_init(qsr_uring_t *ring, unsigned entries) {
  if (ring == nullptr || entries == 0U) {
    return QSR_ERR_INVALID;
  }
  memset(ring, 0, sizeof(*ring));
  ring->fd = -1;
  ring->recv_poll_first = true;
  struct io_uring_params params = {0};
  const int fd = qsr_io_uring_setup(entries, &params);
  if (fd < 0) {
    return QSR_ERR_INVALID;
  }
  ring->fd = fd;

  ring->sq_ring_sz = params.sq_off.array + (size_t)params.sq_entries * sizeof(unsigned);
  ring->cq_ring_sz = params.cq_off.cqes + (size_t)params.cq_entries * sizeof(struct io_uring_cqe);
  if ((params.features & IORING_FEAT_SINGLE_MMAP) != 0U && ring->cq_ring_sz > ring->sq_ring_sz) {
    ring->sq_ring_sz = ring->cq_ring_sz;
  }
  ring->sq_ring = mmap(nullptr, ring->sq_ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
                       IORING_OFF_SQ_RING);
  if (ring->sq_ring == MAP_FAILED) {
    qsr_uring_close(ring);
    return QSR_ERR_INVALID;
  }
  if ((params.features & IORING_FEAT_SINGLE_MMAP) != 0U) {
    ring->cq_ring = ring->sq_ring;
  } else {
    ring->cq_ring = mmap(nullptr, ring->cq_ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
                         IORING_OFF_CQ_RING);
    if (ring->cq_ring == MAP_FAILED) {
      qsr_uring_close(ring);
      return QSR_ERR_INVALID;
    }
  }
  ring->sqes_sz = (size_t)params.sq_entries * sizeof(struct io_uring_sqe);
  ring->sqes = mmap(nullptr, ring->sqes_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
  if (ring->sqes == MAP_FAILED) {
    qsr_uring_close(ring);
    return QSR_ERR_INVALID;
  }

  char *sq = ring->sq_ring;
  char *cq = ring->cq_ring;
  ring->sq_head = (unsigned *)(sq + params.sq_off.head);
  ring->sq_tail = (unsigned *)(sq + params.sq_off.tail);
  ring->sq_ring_mask = (unsigned *)(sq + params.sq_off.ring_mask);
  ring->sq_ring_entries = (unsigned *)(sq + params.sq_off.ring_entries);
  ring->sq_array = (unsigned *)(sq + params.sq_off.array);
  ring->cq_head = (unsigned *)(cq + params.cq_off.head);
  ring->cq_tail = (unsigned *)(cq + params.cq_off.tail);
  ring->cq_ring_mask = (unsigned *)(cq + params.cq_off.ring_mask);
  ring->cqes = (struct io_uring_cqe *)(cq + params.cq_off.cqes);
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t qsr_uring_submit(qsr_uring_t *ring) {
  for (;;) {
    const unsigned head = __atomic_load_n(ring->sq_head, __ATOMIC_ACQUIRE);
    const unsigned tail = __atomic_load_n(ring->sq_tail, __ATOMIC_ACQUIRE);
    const unsigned pending = tail - head;
    if (pending == 0U) {
      return QSR_OK;
    }
    const int submitted = qsr_io_uring_enter(ring->fd, pending, 0U, 0U);
    if (submitted > 0) {
      continue;
    }
    if (submitted == 0) {
      errno = EIO;
      return QSR_ERR_INVALID;
    }
    if (errno == EINTR) {
      continue;
    }
    return QSR_ERR_INVALID;
  }
}

[[nodiscard]] static struct io_uring_cqe *qsr_uring_peek_cqe(qsr_uring_t *ring) {
  const unsigned head = __atomic_load_n(ring->cq_head, __ATOMIC_ACQUIRE);
  const unsigned tail = __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE);
  if (head == tail) {
    return nullptr;
  }
  return &ring->cqes[head & *ring->cq_ring_mask];
}

static void qsr_uring_cqe_seen(qsr_uring_t *ring) {
  const unsigned head = __atomic_load_n(ring->cq_head, __ATOMIC_RELAXED);
  __atomic_store_n(ring->cq_head, head + 1U, __ATOMIC_RELEASE);
}

[[nodiscard]] static struct io_uring_recvmsg_out *qsr_uring_recvmsg_validate(void *buffer, int buffer_len,
                                                                              const struct msghdr *message) {
  if (buffer_len < 0 || (size_t)buffer_len < sizeof(struct io_uring_recvmsg_out)) {
    return nullptr;
  }
  if (buffer == nullptr || message == nullptr) {
    return nullptr;
  }
  const size_t len = (size_t)buffer_len;
  const size_t header_len = sizeof(struct io_uring_recvmsg_out);
  if (message->msg_namelen > len - header_len) {
    return nullptr;
  }
  if (message->msg_controllen > len - header_len - message->msg_namelen) {
    return nullptr;
  }
  return (struct io_uring_recvmsg_out *)buffer;
}

[[nodiscard]] static void *qsr_uring_recvmsg_payload(struct io_uring_recvmsg_out *out,
                                                      const struct msghdr *message) {
  return (uint8_t *)(out + 1) + message->msg_namelen + message->msg_controllen;
}

[[nodiscard]] static size_t qsr_uring_recvmsg_payload_length(struct io_uring_recvmsg_out *out, int buffer_len,
                                                             const struct msghdr *message) {
  const uintptr_t payload_start = (uintptr_t)qsr_uring_recvmsg_payload(out, message);
  const uintptr_t payload_end = (uintptr_t)out + (size_t)buffer_len;
  if (payload_start >= payload_end) {
    return 0U;
  }
  return (size_t)(payload_end - payload_start);
}
#endif

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
    const int result = sendmmsg(fd, &messages[sent], (unsigned int)(sender->count - sent), MSG_DONTWAIT);
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

[[nodiscard]] static bool is_known_backend_addr(const qsr_config_t *runtime_config, const qsr_session_table_t *sessions,
                                                const struct sockaddr_storage *addr, socklen_t addr_len) {
  if (qsr_route_table_has_backend(&runtime_config->routes, addr, addr_len)) {
    return true;
  }

  /*
   * Kubernetes Service/NAT paths can make backend packets arrive from the
   * selected pod tuple rather than the configured Service tuple. Once a packet
   * from that tuple has been routed to a client, remember it as a backend
   * source too; otherwise later stale-Initial and post-idle reset paths treat
   * the pod tuple as a client and can misclassify the session direction.
   */
  const qsr_session_key_t key = qsr_session_tuple_key(addr, addr_len);
  const qsr_session_t *session = qsr_session_table_get(sessions, &key);
  return session != nullptr &&
         !qsr_route_table_has_backend(&runtime_config->routes, &session->backend_addr, session->backend_addr_len);
}

static void learn_long_header_cids(qsr_session_table_t *sessions, const uint8_t *packet, size_t packet_len,
                                   const struct sockaddr_storage *source, socklen_t source_len,
                                   const struct sockaddr_storage *dest, socklen_t dest_len, time_t now) {
  /*
   * Hot-path short-circuit: this is called for every packet of every
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
  qsr_session_key_t scid_key = qsr_session_single_cid_key(header.scid, header.scid_len);
  qsr_session_key_t pair_key = qsr_session_cid_key(header.dcid, header.dcid_len, header.scid, header.scid_len);
  put_alias(sessions, &dcid_key, dest, dest_len, now);
  put_alias(sessions, &scid_key, source, source_len, now);
  put_alias(sessions, &pair_key, dest, dest_len, now);
}

[[nodiscard]] static qsr_session_t *lookup_long_header_request_dcid(const qsr_config_t *runtime_config,
                                                                    const qsr_session_table_t *sessions,
                                                                    const qsr_quic_initial_t *initial) {
  qsr_session_key_t dcid_key = qsr_session_single_cid_key(initial->dcid, initial->dcid_len);
  qsr_session_t *session = qsr_session_table_get(sessions, &dcid_key);
  if (session != nullptr &&
      is_known_backend_addr(runtime_config, sessions, &session->backend_addr, session->backend_addr_len)) {
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
   * stale or attacker-planted aliases — both of which we close by refusing
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

[[nodiscard]] static qsr_session_t *lookup_long_header_response_dcid(const qsr_config_t *runtime_config,
                                                                     const qsr_session_table_t *sessions,
                                                                     const uint8_t *packet, size_t packet_len) {
  qsr_session_t *session = lookup_long_header_dcid(sessions, packet, packet_len);
  if (session != nullptr &&
      !is_known_backend_addr(runtime_config, sessions, &session->backend_addr, session->backend_addr_len)) {
    return session;
  }
  return nullptr;
}

[[nodiscard]] static qsr_session_t *lookup_backend_dcid(const qsr_config_t *runtime_config,
                                                        const qsr_session_table_t *sessions, const uint8_t *packet,
                                                        size_t packet_len) {
  qsr_session_t *session = lookup_long_header_dcid(sessions, packet, packet_len);
  if (session == nullptr) {
    session = lookup_short_header_cid(sessions, packet, packet_len);
  }
  if (session != nullptr &&
      !is_known_backend_addr(runtime_config, sessions, &session->backend_addr, session->backend_addr_len)) {
    return session;
  }
  return nullptr;
}

#ifdef __linux__
[[nodiscard]] static qsr_status_t set_nonblocking(int fd) {
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    return QSR_ERR_INVALID;
  }
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t set_blocking(int fd) {
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
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

static void bind_client_tuple(qsr_session_table_t *sessions, const qsr_session_key_t *new_tuple_key,
                              const struct sockaddr_storage *backend, socklen_t backend_len, time_t now) {
  (void)qsr_session_table_put(sessions, new_tuple_key, backend, backend_len, now);
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

static void handle_packet(const qsr_config_t *runtime_config, qsr_session_table_t *sessions,
                          qsr_pending_initial_table_t *pending_initials, qsr_udp_sender_t *sender, int fd,
                          const uint8_t *packet, size_t packet_len, const struct sockaddr_storage *source,
                          socklen_t source_len, time_t now) {
  qsr_session_key_t key = qsr_session_tuple_key(source, source_len);
  qsr_session_t *session = nullptr;
  const bool source_is_backend = is_known_backend_addr(runtime_config, sessions, source, source_len);
  QSR_PACKET_DECISION_VAR;

  /*
   * Initial packets need careful handling. There are three sub-cases:
   *
   *  1. Client Initial, fresh connection:
   *       - pair-CID miss, no tuple alias (or stale tuple alias from a
   *         reused source port) — route fresh by SNI.
   *  2. Client Initial, retransmission of an already-routed connection:
   *       - pair-CID match — use that session.
   *  3. Server Initial response (during handshake, backend -> client):
   *       - pair-CID miss (server-chosen CIDs not yet learned), tuple
   *         match against a REVERSE alias (backend tuple -> client) —
   *         use the tuple match.
   *
   * The trap is case 1 with a kernel-reused source port: the stale tuple
   * alias from a closed previous connection still maps to a backend, so a
   * bare tuple match misroutes the fresh Initial. The fix is to
   * distinguish (1) from (3) — a tuple match whose destination is a known
   * backend is the port-reuse case; a tuple match whose destination is NOT a
   * known backend is a reverse alias for a backend->client response. Known
   * backends include configured route addresses plus backend source tuples
   * learned from Kubernetes/NAT return traffic.
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
      /* Post-Retry Initials use the backend's Retry SCID as their DCID. Once
       * we have observed the Retry, a DCID alias is enough to route the packet
       * without decrypting/parsing the second ClientHello flight. */
      if (session == nullptr && !source_is_backend) {
        session = lookup_long_header_request_dcid(runtime_config, sessions, &initial);
        if (session != nullptr) {
          QSR_SET_PACKET_DECISION("initial_request_dcid");
        }
      }
      /* Backend Initial responses use DCID = the client's SCID. The client
       * Initial taught us that single-CID alias, and it is per connection;
       * the backend tuple alias is shared by all concurrent handshakes to the
       * same backend and is therefore only a fallback. */
      if (session == nullptr && source_is_backend) {
        qsr_session_key_t dcid_key = qsr_session_single_cid_key(initial.dcid, initial.dcid_len);
        qsr_session_t *dcid_session = qsr_session_table_get(sessions, &dcid_key);
        if (dcid_session != nullptr && !is_known_backend_addr(runtime_config, sessions, &dcid_session->backend_addr,
                                                              dcid_session->backend_addr_len)) {
          session = dcid_session;
          QSR_SET_PACKET_DECISION("backend_initial_dcid");
        }
      }
    }
  }
  if (session == nullptr) {
    session = lookup_long_header_response_dcid(runtime_config, sessions, packet, packet_len);
    if (session != nullptr) {
      QSR_SET_PACKET_DECISION("long_response_dcid");
    }
  }
  if (session == nullptr && source_is_backend) {
    session = lookup_backend_dcid(runtime_config, sessions, packet, packet_len);
    if (session != nullptr) {
      QSR_SET_PACKET_DECISION("backend_dcid");
    }
  }
  if (session == nullptr) {
    qsr_session_t *tuple_session = qsr_session_table_get(sessions, &key);
    /*
     * Honour a tuple match in two cases:
     *   - non-Initial packet (tuple is authoritative within one ephemeral
     *     port's lifetime), or
     *   - Initial whose tuple-matched destination is NOT a configured
     *     backend, which means the destination is a client tuple — i.e., a
     *     REVERSE alias for a backend's Initial response during handshake.
     *
     * The dropped case is the opposite: an Initial whose tuple-matched
     * destination IS a configured backend. That's the source-port-reuse
     * scenario — a fresh client Initial inheriting a stale forward alias
     * from a closed previous connection. Drop the tuple match and let
     * route_initial_datagram below route fresh by SNI.
     */
    if (tuple_session != nullptr &&
        (!is_initial || !is_known_backend_addr(runtime_config, sessions, &tuple_session->backend_addr,
                                               tuple_session->backend_addr_len))) {
      session = tuple_session;
      QSR_SET_PACKET_DECISION("tuple");
    }
  }
  if (session == nullptr) {
    const qsr_session_t *cid_session = lookup_short_header_cid(sessions, packet, packet_len);
    if (cid_session != nullptr) {
      /*
       * NAT rebinding via short-header CID: install the new client tuple. The
       * common direction-refresh block below updates the reverse tuple once the
       * packet has been classified.
       */
      struct sockaddr_storage backend = cid_session->backend_addr;
      const socklen_t backend_len = cid_session->backend_addr_len;
      bind_client_tuple(sessions, &key, &backend, backend_len, now);
      session = qsr_session_table_get(sessions, &key);
      if (session != nullptr) {
        QSR_SET_PACKET_DECISION("short_cid_rebind");
      }
    }
  }
  /*
   * lookup_rebound_initial is the long-header-DCID+SCID-pair lookup we
   * already did above when is_initial is true. Skip the duplicate lookup
   * in that case; the previous tuple-first ordering called it unconditionally.
   */
  if (session == nullptr && !is_initial) {
    qsr_session_key_t cid_key;
    const qsr_session_t *cid_session = lookup_rebound_initial(sessions, packet, packet_len, &cid_key);
    if (cid_session != nullptr) {
      struct sockaddr_storage backend = cid_session->backend_addr;
      const socklen_t backend_len = cid_session->backend_addr_len;
      bind_client_tuple(sessions, &key, &backend, backend_len, now);
      session = qsr_session_table_get(sessions, &key);
      if (session != nullptr) {
        QSR_SET_PACKET_DECISION("rebound_initial");
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
      QSR_PACKET_DEBUG("drop_short_unknown", packet, packet_len, source, source_len, nullptr, 0, source_is_backend, 0);
      return;
    }
    struct sockaddr_storage backend;
    socklen_t backend_len = 0;
    qsr_session_key_t cid_key;
    qsr_pending_initial_t *pending_entry = nullptr;
    qsr_status_t status = route_initial_datagram(runtime_config, pending_initials, packet, packet_len, source,
                                                 source_len, now, &backend, &backend_len, &cid_key, &pending_entry);
    if (status != QSR_OK) {
      QSR_PACKET_DEBUG("buffer_initial", packet, packet_len, source, source_len, nullptr, 0, source_is_backend,
                       (int)status);
      return;
    }
    status = qsr_session_table_put(sessions, &key, &backend, backend_len, now);
    if (status != QSR_OK) {
      QSR_PACKET_DEBUG("drop_session_put", packet, packet_len, source, source_len, &backend, backend_len,
                       source_is_backend, (int)status);
      return;
    }
    put_alias(sessions, &cid_key, &backend, backend_len, now);
    learn_long_header_cids(sessions, packet, packet_len, source, source_len, &backend, backend_len, now);
    session = qsr_session_table_get(sessions, &key);
    if (session == nullptr) {
      QSR_PACKET_DEBUG("drop_session_get", packet, packet_len, source, source_len, &backend, backend_len,
                       source_is_backend, 0);
      return;
    }
    QSR_SET_PACKET_DECISION("fresh_sni");
    qsr_session_key_t reverse_key = qsr_session_tuple_key(&backend, backend_len);
    (void)qsr_session_table_put(sessions, &reverse_key, source, source_len, now);
    if (pending_entry != nullptr) {
      for (size_t i = 0U; i < pending_entry->packet_count; i++) {
        QSR_PACKET_DEBUG(QSR_PACKET_DECISION, pending_entry->packets[i], pending_entry->packet_lens[i], source,
                         source_len, &backend, backend_len, source_is_backend, 0);
        sender_enqueue(sender, fd, pending_entry->packets[i], pending_entry->packet_lens[i], &backend, backend_len);
      }
      pending_initial_remove(pending_initials, pending_entry);
      return;
    }
  }

  session->last_seen = now;
  const bool destination_is_backend =
      is_known_backend_addr(runtime_config, sessions, &session->backend_addr, session->backend_addr_len);
  if (destination_is_backend) {
    /*
     * Refresh the backend->client reverse tuple on every client packet. This
     * is the only route available for QUIC stateless resets, whose bytes are
     * deliberately indistinguishable from random short-header packets and
     * cannot be CID-routed by a non-terminating proxy. Without this refresh, a
     * backend idle timeout can produce a reset that follows a stale reverse
     * tuple to another client, leaving the real client to time out with a
     * browser-level QUIC protocol error.
     */
    qsr_session_key_t reverse_key = qsr_session_tuple_key(&session->backend_addr, session->backend_addr_len);
    (void)qsr_session_table_put(sessions, &reverse_key, source, source_len, now);
  } else {
    /* Backend -> client, possibly from a Kubernetes pod tuple instead of the
     * configured Service tuple. Pin subsequent client packets to the observed
     * backend source so a later stateless reset returns on the same tuple. */
    qsr_session_key_t client_key = qsr_session_tuple_key(&session->backend_addr, session->backend_addr_len);
    (void)qsr_session_table_put(sessions, &client_key, source, source_len, now);
    (void)qsr_session_table_put(sessions, &key, &session->backend_addr, session->backend_addr_len, now);
  }
  /*
   * Learning is cheap and idempotent: re-running here picks up CID rotations
   * on coalesced Initial+Handshake datagrams from either direction.
   */
  learn_long_header_cids(sessions, packet, packet_len, source, source_len, &session->backend_addr,
                         session->backend_addr_len, now);
  QSR_PACKET_DEBUG(QSR_PACKET_DECISION, packet, packet_len, source, source_len, &session->backend_addr,
                   session->backend_addr_len, source_is_backend, 0);
  sender_enqueue(sender, fd, packet, packet_len, &session->backend_addr, session->backend_addr_len);
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
  qsr_uring_t uring;
  if (qsr_uring_init(&uring, QSR_UDP_BATCH_SIZE * 2U) != QSR_OK) {
    fprintf(stderr, "quic-sni-router: io_uring setup failed: %s\n", strerror(errno));
    (void)close(fd);
    qsr_runtime_free(&runtime);
    return QSR_ERR_INVALID;
  }
  if (qsr_uring_register_recv_buffers(&uring) != QSR_OK) {
    fprintf(stderr, "quic-sni-router: io_uring multishot receive buffers unavailable: %s\n", strerror(errno));
    qsr_uring_close(&uring);
    (void)close(fd);
    qsr_runtime_free(&runtime);
    return QSR_ERR_UNSUPPORTED;
  }
  int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (epoll_fd < 0) {
    qsr_uring_close(&uring);
    (void)close(fd);
    qsr_runtime_free(&runtime);
    return QSR_ERR_INVALID;
  }
  struct epoll_event event = {.events = EPOLLIN, .data.fd = uring.fd};
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, uring.fd, &event) < 0) {
    (void)close(epoll_fd);
    qsr_uring_close(&uring);
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
  fprintf(stderr, "quic-sni-router dataplane: io_uring recvmsg + sendmmsg\n");
#else
  fprintf(stderr, "quic-sni-router dataplane: recvfrom/sendto\n");
#endif

  time_t last_expire = monotonic_now();
  qsr_udp_sender_t sender;
  qsr_pending_initial_table_t *pending_initials = calloc(1U, sizeof(*pending_initials));
  if (pending_initials == nullptr) {
    (void)close(fd);
    qsr_runtime_free(&runtime);
#ifdef __linux__
    qsr_uring_close(&uring);
    (void)close(epoll_fd);
#endif
    return QSR_ERR_FULL;
  }
  sender_init(&sender);
#ifdef __linux__
  struct msghdr recv_message = {.msg_namelen = sizeof(struct sockaddr_storage), .msg_controllen = 0U};
  if (qsr_uring_recvmsg_multishot(&uring, fd, &recv_message) != QSR_OK || qsr_uring_submit(&uring) != QSR_OK) {
    fprintf(stderr, "quic-sni-router: io_uring multishot receive submit failed: %s\n", strerror(errno));
    free(pending_initials);
    qsr_runtime_free(&runtime);
    qsr_uring_close(&uring);
    (void)close(epoll_fd);
    (void)close(fd);
    return QSR_ERR_INVALID;
  }
#endif
  while (!g_stop) {
#ifdef __linux__
    qsr_runtime_poll(&runtime);
    size_t completed = 0U;
    bool uring_failed = false;
    const struct io_uring_cqe *cqe;
    while ((cqe = qsr_uring_peek_cqe(&uring)) != nullptr) {
      const uint64_t user_data = cqe->user_data;
      const int result = cqe->res;
      const unsigned cqe_flags = cqe->flags;
      qsr_uring_cqe_seen(&uring);
      if (user_data != QSR_URING_MULTISHOT_USER_DATA) {
        continue;
      }
      const bool recv_armed = (cqe_flags & IORING_CQE_F_MORE) != 0U;
      const time_t now = monotonic_now();
      uint16_t buffer_id = 0U;
      bool recycle_buffer = false;
      if ((cqe_flags & IORING_CQE_F_BUFFER) != 0U) {
        buffer_id = (uint16_t)(cqe_flags >> IORING_CQE_BUFFER_SHIFT);
        recycle_buffer = buffer_id < QSR_URING_RECV_BUFFERS;
      }
      if (result >= 0) {
        if (!recycle_buffer) {
          fprintf(stderr, "quic-sni-router: io_uring recvmsg missing provided buffer\n");
          uring_failed = true;
          break;
        }
        void *buffer = &uring.recv_buffers[(size_t)buffer_id * QSR_URING_RECV_BUFFER_SIZE];
        struct io_uring_recvmsg_out *out = qsr_uring_recvmsg_validate(buffer, result, &recv_message);
        const size_t payload_len =
            out == nullptr ? 0U : qsr_uring_recvmsg_payload_length(out, result, &recv_message);
        if (out == nullptr || payload_len == 0U || payload_len > QSR_MAX_DATAGRAM_SIZE ||
            out->namelen > sizeof(struct sockaddr_storage)) {
          qsr_uring_buf_ring_add(&uring, buffer_id, 0U);
          qsr_uring_buf_ring_advance(&uring, 1U);
          if (!recv_armed &&
              (qsr_uring_recvmsg_multishot(&uring, fd, &recv_message) != QSR_OK || qsr_uring_submit(&uring) != QSR_OK)) {
            fprintf(stderr, "quic-sni-router: io_uring multishot receive requeue failed\n");
            uring_failed = true;
            break;
          }
          continue;
        }
        const struct sockaddr_storage *source = (const struct sockaddr_storage *)(out + 1);
        const uint8_t *packet = qsr_uring_recvmsg_payload(out, &recv_message);
        handle_packet(&runtime.config, &runtime.sessions, pending_initials, &sender, fd, packet,
                      payload_len, source, (socklen_t)out->namelen, now);
        qsr_uring_buf_ring_add(&uring, buffer_id, 0U);
        qsr_uring_buf_ring_advance(&uring, 1U);
      } else if (result == -EINVAL && uring.recv_poll_first) {
        uring.recv_poll_first = false;
        if (set_blocking(fd) != QSR_OK) {
          fprintf(stderr, "quic-sni-router: failed to switch socket to blocking io_uring receives\n");
          uring_failed = true;
          break;
        }
        fprintf(stderr, "quic-sni-router: io_uring POLL_FIRST unsupported; using blocking recv SQEs\n");
      } else if (result == -EAGAIN || result == -EWOULDBLOCK) {
        /* POLL_FIRST should make this rare on idle sockets; re-arm without treating it as progress. */
      } else {
        errno = -result;
        fprintf(stderr, "quic-sni-router: io_uring recvmsg failed: %s\n", strerror(errno));
        uring_failed = true;
        break;
      }
      if (!recv_armed) {
        if (qsr_uring_recvmsg_multishot(&uring, fd, &recv_message) != QSR_OK || qsr_uring_submit(&uring) != QSR_OK) {
          fprintf(stderr, "quic-sni-router: io_uring multishot receive requeue failed: %s\n", strerror(errno));
          uring_failed = true;
          break;
        }
      }
      if (result >= 0) {
        completed++;
      }
    }
    if (uring_failed) {
      break;
    }
    if (completed > 0U) {
      if (qsr_uring_submit(&uring) != QSR_OK) {
        fprintf(stderr, "quic-sni-router: io_uring submit failed: %s\n", strerror(errno));
        break;
      }
      sender_flush(&sender, fd);
      const time_t now = monotonic_now();
      if (now - last_expire >= QSR_EXPIRE_SWEEP_INTERVAL_SECONDS) {
        (void)qsr_session_table_expire_incremental(&runtime.sessions, now, (time_t)runtime.config.idle_timeout_seconds,
                                                   session_expire_scan_budget(&runtime.sessions));
        pending_initial_expire(pending_initials, now);
        last_expire = now;
      }
      continue;
    }
    if (qsr_uring_submit(&uring) != QSR_OK) {
      fprintf(stderr, "quic-sni-router: io_uring submit failed: %s\n", strerror(errno));
      break;
    }
    if (wait_readable(epoll_fd) != QSR_OK) {
      break;
    }
    const time_t now = monotonic_now();
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
    handle_packet(&runtime.config, &runtime.sessions, pending_initials, &sender, fd, packet, (size_t)received, &source,
                  source_len, now);
    sender_flush(&sender, fd);
#endif
    if (now - last_expire >= QSR_EXPIRE_SWEEP_INTERVAL_SECONDS) {
      (void)qsr_session_table_expire_incremental(&runtime.sessions, now, (time_t)runtime.config.idle_timeout_seconds,
                                                 session_expire_scan_budget(&runtime.sessions));
      pending_initial_expire(pending_initials, now);
      last_expire = now;
    }
  }

  sender_flush(&sender, fd);
  fprintf(stderr, "quic-sni-router: shutting down\n");
  free(pending_initials);
  qsr_runtime_free(&runtime);
#ifdef __linux__
  qsr_uring_close(&uring);
  (void)close(epoll_fd);
#endif
  (void)close(fd);
  return QSR_OK;
}
