/* Exercise the real packet handlers without exporting test-only production APIs. */
#include "../../src/udp.c" // NOLINT(bugprone-suspicious-include): test internal packet handlers.
#include "test_main.h"
#include <openssl/evp.h>
#include <sys/wait.h>

static const char *seed_directory;

static void save_seed(const char *name, const uint8_t *data, size_t len) {
  if (seed_directory == nullptr) {
    return;
  }
  char path[4096];
  ASSERT_TRUE(snprintf(path, sizeof(path), "%s/%s", seed_directory, name) < (int)sizeof(path));
  FILE *file = fopen(path, "wb");
  ASSERT_TRUE(file != nullptr && fwrite(data, 1, len, file) == len && fclose(file) == 0);
}

static struct sockaddr_storage loopback(unsigned port) {
  struct sockaddr_storage addr = {0};
  struct sockaddr_in *v4 = (struct sockaddr_in *)&addr;
  v4->sin_family = AF_INET;
  v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  v4->sin_port = htons((uint16_t)port);
  return addr;
}

static int bound_socket(struct sockaddr_storage *addr) {
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_TRUE(fd >= 0);
  *addr = loopback(0);
  ASSERT_TRUE(bind(fd, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) == 0);
  socklen_t len = sizeof(*addr);
  ASSERT_TRUE(getsockname(fd, (struct sockaddr *)addr, &len) == 0);
  return fd;
}

static void test_flow_lifetimes_and_sources(void) {
  qsr_runtime_t *runtime = calloc(1, sizeof(*runtime));
  ASSERT_TRUE(runtime != nullptr);
  ASSERT_TRUE(qsr_flow_table_init(&runtime->flows, 4) == QSR_OK);
  ASSERT_TRUE(qsr_session_table_init(&runtime->sessions, 1) == QSR_OK);
  qsr_dataplane_t dp = {.runtime = runtime, .epoll_fd = epoll_create1(EPOLL_CLOEXEC)};
  ASSERT_TRUE(dp.epoll_fd >= 0);
  runtime->flows.on_close = conn_close_callback;
  runtime->flows.on_close_userdata = &dp;
  struct sockaddr_storage client;
  struct sockaddr_storage backend;
  struct sockaddr_storage attacker;
  int client_fd = bound_socket(&client);
  int backend_fd = bound_socket(&backend);
  int attacker_fd = bound_socket(&attacker);
  dp.main_fd = attacker_fd;
  qsr_flow_t *flow = flow_acquire(&dp, &client, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in),
                                 1, nullptr, nullptr, 0);
  ASSERT_TRUE(flow != nullptr);
  struct sockaddr_storage upstream = {0};
  socklen_t len = sizeof(upstream);
  ASSERT_TRUE(getsockname(flow->fd, (struct sockaddr *)&upstream, &len) == 0);
  ASSERT_TRUE(sendto(attacker_fd, "bad", 3, 0, (struct sockaddr *)&upstream, len) == 3);
  ASSERT_TRUE(sendto(backend_fd, "good", 4, 0, (struct sockaddr *)&upstream, len) == 4);
  char buffer[32];
  ASSERT_TRUE(recv(flow->fd, buffer, sizeof(buffer), 0) == 4 && memcmp(buffer, "good", 4) == 0);
  ASSERT_TRUE(recv(flow->fd, buffer, sizeof(buffer), 0) < 0 && errno == EAGAIN);

  /* Learning into a one-entry table used to clear the borrowed destination. */
  qsr_session_key_t tuple = qsr_session_tuple_key(&client, sizeof(struct sockaddr_in));
  ASSERT_TRUE(qsr_session_table_put(&runtime->sessions, &tuple, &backend, sizeof(struct sockaddr_in), 1) == QSR_OK);
  uint8_t handshake[23] = {0xe0,0,0,0,1,8,1,2,3,4,5,6,7,8,8,11,12,13,14,15,16,17,18};
  handle_client_packet(&dp, handshake, sizeof(handshake), &client, sizeof(struct sockaddr_in), 2);
  ASSERT_TRUE(dp.sender.count == 1 && dp.sender.items[0].dest_len == 0);
  ASSERT_TRUE(memcmp(&runtime->sessions.sessions[0].backend_addr, &backend, sizeof(backend)) == 0);
  int old_fd = flow->fd;
  qsr_flow_table_remove(&runtime->flows, flow);
  ASSERT_TRUE(dp.sender.count == 0); /* Must flush before the fd can be recycled. */
  ASSERT_TRUE(recv(backend_fd, buffer, sizeof(buffer), 0) == sizeof(handshake));
  ASSERT_TRUE(fcntl(old_fd, F_GETFD) < 0 && errno == EBADF);

  /* An address-family change must allocate a socket for the new backend. */
  flow = flow_acquire(&dp, &client, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in),
                      3, nullptr, nullptr, 0);
  ASSERT_TRUE(flow != nullptr);
  struct sockaddr_storage v6 = {0};
  struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&v6;
  s6->sin6_family = AF_INET6;
  s6->sin6_addr = in6addr_loopback;
  s6->sin6_port = htons(8443);
  flow = flow_acquire(&dp, &client, sizeof(struct sockaddr_in), &v6, sizeof(*s6), 4, nullptr, nullptr, 0);
  ASSERT_TRUE(flow != nullptr);
  len = sizeof(upstream);
  ASSERT_TRUE(getsockname(flow->fd, (struct sockaddr *)&upstream, &len) == 0 && upstream.ss_family == AF_INET6);
  qsr_flow_table_free(&runtime->flows);
  qsr_session_table_free(&runtime->sessions);
  close(dp.epoll_fd);
  close(client_fd);
  close(backend_fd);
  close(attacker_fd);
  free(runtime);
}

static void test_socket_marks(void) {
  /* Zero must not even call setsockopt; errors must preserve errno. */
  ASSERT_TRUE(set_socket_mark(-1, 0, "listener") == QSR_OK);
  ASSERT_TRUE(set_socket_mark(-1, 12345, "listener") == QSR_ERR_INVALID && errno == EBADF);
  const int families[] = {AF_INET, AF_INET6};
  for (size_t i = 0; i < sizeof(families) / sizeof(families[0]); i++) {
    int listener = socket(families[i], SOCK_DGRAM | SOCK_CLOEXEC, 0);
    ASSERT_TRUE(listener >= 0);
    uint32_t actual = UINT32_MAX;
    socklen_t len = sizeof(actual);
    ASSERT_TRUE(set_socket_mark(listener, 0, "listener") == QSR_OK);
    ASSERT_TRUE(getsockopt(listener, SOL_SOCKET, SO_MARK, &actual, &len) == 0 && actual == 0);
    const qsr_status_t marked = set_socket_mark(listener, UINT32_MAX, "listener");
    if (marked == QSR_OK) {
      ASSERT_TRUE(getsockopt(listener, SOL_SOCKET, SO_MARK, &actual, &len) == 0 && actual == UINT32_MAX);
    } else {
      ASSERT_TRUE(errno == EPERM || errno == EACCES);
    }
    close(listener);

    qsr_runtime_t *runtime = calloc(1, sizeof(*runtime));
    ASSERT_TRUE(runtime != nullptr);
    qsr_config_default(&runtime->config);
    runtime->config.fwmark = marked == QSR_OK ? UINT32_MAX : 12345;
    ASSERT_TRUE(qsr_flow_table_init(&runtime->flows, 4) == QSR_OK);
    qsr_dataplane_t dp = {.runtime = runtime, .epoll_fd = epoll_create1(EPOLL_CLOEXEC)};
    ASSERT_TRUE(dp.epoll_fd >= 0);
    struct sockaddr_storage backend = loopback(8443);
    socklen_t backend_len = sizeof(struct sockaddr_in);
    if (families[i] == AF_INET6) {
      memset(&backend, 0, sizeof(backend));
      struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&backend;
      v6->sin6_family = AF_INET6;
      v6->sin6_addr = in6addr_loopback;
      v6->sin6_port = htons(8443);
      backend_len = sizeof(*v6);
    }
    const struct sockaddr_storage client = loopback(40000);
    const qsr_flow_t *flow = flow_acquire(&dp, &client, sizeof(struct sockaddr_in), &backend, backend_len,
                                          1, nullptr, nullptr, 0);
    if (marked == QSR_OK) {
      ASSERT_TRUE(flow != nullptr);
      ASSERT_TRUE(getsockopt(flow->fd, SOL_SOCKET, SO_MARK, &actual, &len) == 0 && actual == UINT32_MAX);
    } else {
      ASSERT_TRUE(flow == nullptr && runtime->flows.count == 0 && dp.metrics.flow_open_failures == 1);
      runtime->config.max_sessions = 4;
      strcpy(runtime->config.listen_udp, "127.0.0.1:8443");
      ASSERT_TRUE(qsr_udp_run(&runtime->config, nullptr) == QSR_ERR_INVALID);
    }
    qsr_flow_table_free(&runtime->flows);
    close(dp.epoll_fd);
    free(runtime);
  }
}

static void test_pressure_eviction(void) {
  qsr_session_table_t table;
  ASSERT_TRUE(qsr_session_table_init(&table, 1024) == QSR_OK);
  struct sockaddr_storage backend = loopback(8443);
  for (uint64_t i = 0; i < 923; i++) {
    qsr_session_key_t key = qsr_session_single_cid_key((uint8_t *)&i, sizeof(i));
    ASSERT_TRUE(qsr_session_table_put(&table, &key, &backend, sizeof(struct sockaddr_in), (time_t)i) == QSR_OK);
  }
  ASSERT_TRUE(table.count == 922 && table.evictions == 1);
  qsr_session_table_free(&table);
  qsr_flow_table_t flows;
  ASSERT_TRUE(qsr_flow_table_init(&flows, 8192) == QSR_OK);
  const struct sockaddr_storage client = loopback(40000);
  const int fd = open("/dev/null", O_RDONLY);
  ASSERT_TRUE(fd >= 0);
  ASSERT_TRUE(qsr_flow_table_put(&flows, &client, sizeof(struct sockaddr_in), &backend,
                                  sizeof(struct sockaddr_in), fd, 1) != nullptr);
  flows.evict_cursor = 4096; /* First sample is empty, but a reclaimable fd exists. */
  ASSERT_TRUE(qsr_flow_table_evict_oldest(&flows) == 1 && flows.count == 0);
  qsr_flow_table_free(&flows);
}

static void test_gro_and_gso(void) {
  struct sockaddr_storage destination;
  int receiver = bound_socket(&destination);
  int one = 1;
  ASSERT_TRUE(setsockopt(receiver, IPPROTO_UDP, UDP_GRO, &one, sizeof(one)) == 0);
  int source = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  ASSERT_TRUE(source >= 0);
  uint8_t packet[1200];
  memset(packet, 0x40, sizeof(packet));
  qsr_metrics_t metrics = {0};
  qsr_udp_sender_t sender = {.metrics = &metrics};
  for (unsigned i = 0; i < 48; i++) {
    sender_enqueue(&sender, source, packet, sizeof(packet), &destination, sizeof(struct sockaddr_in));
  }
  sender_flush(&sender);
  ASSERT_TRUE(metrics.datagrams_out == 48 && metrics.gso_batches == 1);
  qsr_recv_batch_t batch;
  ASSERT_TRUE(recv_batch_init(&batch) == QSR_OK);
  batch.messages[0].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
  batch.messages[0].msg_hdr.msg_controllen = QSR_UDP_RECV_CMSG_SIZE;
  ASSERT_TRUE(recvmmsg(receiver, batch.messages, 1, MSG_DONTWAIT, nullptr) == 1);
  ASSERT_TRUE(batch.messages[0].msg_len == 48U * sizeof(packet));
  ASSERT_TRUE((batch.messages[0].msg_hdr.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0);
  recv_batch_free(&batch);
  int zero = 0;
  ASSERT_TRUE(setsockopt(receiver, IPPROTO_UDP, UDP_GRO, &zero, sizeof(zero)) == 0);
  ASSERT_TRUE(connect(source, (struct sockaddr *)&destination, sizeof(struct sockaddr_in)) == 0);
  sender.gso_disabled = true;
  sender_enqueue(&sender, source, packet, sizeof(packet), nullptr, 0);
  sender_enqueue(&sender, source, packet, sizeof(packet), nullptr, 0);
  sender_flush(&sender);
  uint8_t received[1500];
  ASSERT_TRUE(recv(receiver, received, sizeof(received), 0) == sizeof(packet));
  ASSERT_TRUE(recv(receiver, received, sizeof(received), 0) == sizeof(packet));
  ASSERT_TRUE(metrics.datagrams_out == 50 && metrics.gso_batches == 1);
  sender_enqueue(&sender, -1, packet, sizeof(packet), nullptr, 0);
  sender_flush(&sender);
  ASSERT_TRUE(metrics.send_drops == 1 && metrics.send_errors[EBADF] == 1);
  close(receiver);
  close(source);
}

static void test_listen_addresses(void) {
  char host[64];
  char port[16];
  ASSERT_TRUE(split_listen("[::1]:8443", host, sizeof(host), port, sizeof(port)) == QSR_OK);
  ASSERT_TRUE(strcmp(host, "::1") == 0 && strcmp(port, "8443") == 0);
  ASSERT_TRUE(split_listen("[::1:8443", host, sizeof(host), port, sizeof(port)) == QSR_ERR_INVALID);
  ASSERT_TRUE(split_listen(":65536", host, sizeof(host), port, sizeof(port)) == QSR_ERR_INVALID);
}

static void test_reply_source_address(void) {
  qsr_runtime_t *runtime = calloc(1, sizeof(*runtime));
  ASSERT_TRUE(runtime != nullptr);
  ASSERT_TRUE(qsr_flow_table_init(&runtime->flows, 4) == QSR_OK);
  qsr_dataplane_t dp = {.runtime = runtime, .epoll_fd = epoll_create1(EPOLL_CLOEXEC)};
  struct sockaddr_storage client;
  struct sockaddr_storage backend;
  struct sockaddr_storage listener = loopback(0);
  ((struct sockaddr_in *)&listener)->sin_addr.s_addr = INADDR_ANY;
  int client_fd = bound_socket(&client);
  int backend_fd = bound_socket(&backend);
  dp.main_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
  struct addrinfo ai = {.ai_family = AF_INET};
  ASSERT_TRUE(configure_socket(dp.main_fd, &ai) == QSR_OK);
  ASSERT_TRUE(bind(dp.main_fd, (struct sockaddr *)&listener, sizeof(struct sockaddr_in)) == 0);
  socklen_t len = sizeof(listener);
  ASSERT_TRUE(getsockname(dp.main_fd, (struct sockaddr *)&listener, &len) == 0);
  ((struct sockaddr_in *)&listener)->sin_addr.s_addr = htonl(0x7f000002U);
  qsr_flow_t *flow = flow_acquire(&dp, &client, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in),
                                 1, nullptr, nullptr, 0);
  ASSERT_TRUE(flow != nullptr);
  const uint8_t packet[] = {0x40, 1, 2, 3};
  ASSERT_TRUE(sendto(client_fd, packet, sizeof(packet), 0, (struct sockaddr *)&listener, len) == sizeof(packet));
  qsr_recv_batch_t batch;
  ASSERT_TRUE(recv_batch_init(&batch) == QSR_OK);
  drain_socket(&dp, &batch, dp.main_fd, nullptr);
  struct sockaddr_storage upstream = {0};
  len = sizeof(upstream);
  char buffer[32];
  ASSERT_TRUE(recvfrom(backend_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&upstream, &len) == sizeof(packet));
  ASSERT_TRUE(sendto(backend_fd, packet, sizeof(packet), 0, (struct sockaddr *)&upstream, len) == sizeof(packet));
  drain_socket(&dp, &batch, flow->fd, flow);
  struct sockaddr_in reply_source = {0};
  len = sizeof(reply_source);
  ASSERT_TRUE(recvfrom(client_fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&reply_source, &len) == sizeof(packet));
  ASSERT_TRUE(reply_source.sin_addr.s_addr == htonl(0x7f000002U));
  recv_batch_free(&batch);
  qsr_flow_table_free(&runtime->flows);
  close(dp.main_fd);
  close(dp.epoll_fd);
  close(client_fd);
  close(backend_fd);
  free(runtime);
}

static void finish_reload(qsr_runtime_t *runtime) {
  const struct timespec delay = {.tv_nsec = 10000000};
  for (unsigned i = 0; i < 200; i++) {
    qsr_runtime_poll(runtime);
    if (runtime->reload_job == nullptr && !runtime->reload_pending) {
      return;
    }
    nanosleep(&delay, nullptr);
  }
  ASSERT_TRUE(false);
}

static void test_completed_reload(void) {
  char dir[] = "/tmp/qsr-reload-test-XXXXXX";
  ASSERT_TRUE(mkdtemp(dir) != nullptr);
  char path[256];
  char other[256];
  snprintf(path, sizeof(path), "%s/config.yaml", dir);
  snprintf(other, sizeof(other), "%s/unrelated", dir);
  const char config[] = "routes: {example.test: {host: 127.0.0.1, port: 8443}}\n";
  FILE *file = fopen(path, "w");
  ASSERT_TRUE(file != nullptr);
  ASSERT_TRUE(fputs(config, file) >= 0 && fclose(file) == 0);
  qsr_config_t *initial = malloc(sizeof(*initial));
  qsr_runtime_t *runtime = calloc(1, sizeof(*runtime));
  ASSERT_TRUE(initial != nullptr && runtime != nullptr);
  ASSERT_TRUE(qsr_config_load(path, initial) == QSR_OK);
  ASSERT_TRUE(qsr_runtime_init(runtime, initial, path) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_resolve(&runtime->config.routes) == QSR_OK);
  int editing = open(path, O_WRONLY | O_TRUNC);
  ASSERT_TRUE(editing >= 0);
  qsr_runtime_poll(runtime);
  ASSERT_TRUE(runtime->reload_job == nullptr && runtime->config.routes.count == 1);
  ASSERT_TRUE(write(editing, config, sizeof(config) - 1U) == sizeof(config) - 1U);
  qsr_runtime_poll(runtime);
  ASSERT_TRUE(runtime->reload_job == nullptr);
  close(editing);
  finish_reload(runtime);
  ASSERT_TRUE(runtime->config.routes.count == 1);
  file = fopen(other, "w");
  ASSERT_TRUE(file != nullptr);
  fclose(file);
  qsr_runtime_poll(runtime);
  ASSERT_TRUE(runtime->reload_job == nullptr);
  file = fopen(other, "w");
  ASSERT_TRUE(file != nullptr);
  ASSERT_TRUE(fputs("listen: {fwmark: 12345}\nsessions: {idleTimeout: 7s}\n"
                    "routes: {example.test: {host: 127.0.0.1, port: 8443}}\n", file) >= 0);
  fclose(file);
  ASSERT_TRUE(rename(other, path) == 0);
  finish_reload(runtime);
  ASSERT_TRUE(runtime->config.idle_timeout_seconds == 7 && runtime->config.routes.count == 1);
  ASSERT_TRUE(runtime->config.fwmark == 0);
  file = fopen(path, "w");
  ASSERT_TRUE(file != nullptr);
  ASSERT_TRUE(fputs("routes: [broken", file) >= 0);
  fclose(file);
  finish_reload(runtime);
  ASSERT_TRUE(runtime->config.idle_timeout_seconds == 7 && runtime->config.routes.count == 1);
  qsr_runtime_free(runtime);
  free(runtime);
  free(initial);
  unlink(path);
  rmdir(dir);
}

static void test_kubernetes_symlink_reload(void) {
  char dir[] = "/tmp/qsr-configmap-test-XXXXXX";
  ASSERT_TRUE(mkdtemp(dir) != nullptr);
  const char *names[] = {"router.yaml", "version1", "version2", "..data", "..data_tmp"};
  char paths[5][256];
  for (size_t i = 0; i < 5; i++) {
    snprintf(paths[i], sizeof(paths[i]), "%s/%s", dir, names[i]);
  }
  for (unsigned i = 1; i <= 2; i++) {
    FILE *file = fopen(paths[i], "w");
    ASSERT_TRUE(file != nullptr);
    ASSERT_TRUE(fprintf(file, "sessions: {idleTimeout: %us, maxSessions: 16}\n"
                             "quicLb: {configurations: [{id: %u, serverIdLength: 3, nonceLength: 4}]}\n"
                             "routes: {example.test: {host: 127.0.0.1, port: 8443, quicLbServerIds: {%u: 'ed793a'}}}\n",
                        i * 7, i - 1U, i - 1U) > 0);
    ASSERT_TRUE(fclose(file) == 0);
  }
  ASSERT_TRUE(symlink("..data", paths[0]) == 0 && symlink("version1", paths[3]) == 0);
  qsr_config_t *config = malloc(sizeof(*config));
  qsr_runtime_t *runtime = calloc(1, sizeof(*runtime));
  ASSERT_TRUE(config != nullptr && runtime != nullptr);
  ASSERT_TRUE(qsr_config_load(paths[0], config) == QSR_OK);
  ASSERT_TRUE(qsr_runtime_init(runtime, config, paths[0]) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_resolve(&runtime->config.routes) == QSR_OK);
  ASSERT_TRUE(runtime->config.idle_timeout_seconds == 7);
  ASSERT_TRUE(runtime->config.quic_lb.configs[0].active && !runtime->config.quic_lb.configs[1].active);
  ASSERT_TRUE(symlink("version2", paths[4]) == 0 && rename(paths[4], paths[3]) == 0);
  finish_reload(runtime);
  ASSERT_TRUE(runtime->config.idle_timeout_seconds == 14 && runtime->config.routes.count == 1);
  ASSERT_TRUE(!runtime->config.quic_lb.configs[0].active && runtime->config.quic_lb.configs[1].active);
  const qsr_quic_lb_server_id_t sid = {.bytes = {0xed, 0x79, 0x3a}, .len = 3};
  ASSERT_TRUE(qsr_route_table_lookup_quic_lb(&runtime->config.routes, 0, &sid) == nullptr);
  ASSERT_TRUE(qsr_route_table_lookup_quic_lb(&runtime->config.routes, 1, &sid) != nullptr);
  qsr_runtime_free(runtime);
  free(runtime);
  free(config);
  for (size_t i = 0; i < 4; i++) {
    ASSERT_TRUE(unlink(paths[i]) == 0);
  }
  ASSERT_TRUE(rmdir(dir) == 0);
}

/* Two protected Initials in one 1200-byte UDP datagram, with SNI split across
 * their CRYPTO frames. Construct real AEAD/header protection, not parser mocks. */
static void protect_initial(uint8_t packet[600], uint32_t version, uint8_t pn,
                            const uint8_t *fragment, uint8_t offset, uint8_t len) {
  memset(packet, 0, 600);
  packet[0] = version == QSR_QUIC_V1 ? 0xc3 : 0xd3;
  for (unsigned i = 0; i < 4; i++) {
    packet[1U + i] = (uint8_t)(version >> (24U - 8U * i));
  }
  packet[5] = 8;
  const uint8_t dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  memcpy(packet + 6, dcid, sizeof(dcid));
  packet[14] = 8;
  const uint8_t scid[8] = {8, 7, 6, 5, 4, 3, 2, 1};
  memcpy(packet + 15, scid, sizeof(scid));
  packet[24] = 0x42;
  packet[25] = 0x3e; /* 574 = PN(4) + ciphertext(554) + tag(16) */
  packet[29] = pn;
  uint8_t plain[554] = {6, offset, len};
  size_t header_len = 3;
  if (len >= 64) {
    plain[2] = 0x40;
    plain[3] = len;
    header_len++;
  }
  memcpy(plain + header_len, fragment, len);
  save_seed("frames/crypto", plain, sizeof(plain));
  qsr_initial_keys_t keys;
  ASSERT_TRUE(qsr_quic_initial_client_keys(version, packet + 6, 8, &keys) == QSR_OK);
  keys.iv[11] ^= pn;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ASSERT_TRUE(ctx != nullptr);
  int written = 0;
  ASSERT_TRUE(EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, keys.key, keys.iv) == 1);
  ASSERT_TRUE(EVP_EncryptUpdate(ctx, nullptr, &written, packet, 30) == 1);
  ASSERT_TRUE(EVP_EncryptUpdate(ctx, packet + 30, &written, plain, sizeof(plain)) == 1 && written == sizeof(plain));
  ASSERT_TRUE(EVP_EncryptFinal_ex(ctx, packet + 584, &written) == 1);
  ASSERT_TRUE(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, packet + 584) == 1);
  uint8_t mask[32];
  ASSERT_TRUE(EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, keys.hp, nullptr) == 1);
  ASSERT_TRUE(EVP_CIPHER_CTX_set_padding(ctx, 0) == 1);
  ASSERT_TRUE(EVP_EncryptUpdate(ctx, mask, &written, packet + 30, 16) == 1 && written == 16);
  packet[0] ^= mask[0] & 0x0f;
  for (unsigned i = 0; i < 4; i++) {
    packet[26U + i] ^= mask[1U + i];
  }
  EVP_CIPHER_CTX_free(ctx);
}

static void test_coalesced_initials(void) {
  uint8_t hello[77] = {1,0,0,73,3,3};
  const uint8_t tail[] = {0,0,2,0x13,1,1,0,0,30,0,0,0,26,0,24,0,0,21,
                          'r','v','r','-','a','.','f','l','i','g','h','t','d','e','c','k','.','t','e','s','t'};
  memcpy(hello + 38, tail, sizeof(tail));
  save_seed("tls/hello", hello, sizeof(hello));
  qsr_config_t *config = malloc(sizeof(*config));
  qsr_pending_initial_table_t *pending = calloc(1, sizeof(*pending));
  ASSERT_TRUE(config != nullptr && pending != nullptr);
  qsr_config_default(config);
  ASSERT_TRUE(qsr_route_table_add(&config->routes, "rvr-a.flightdeck.test", "127.0.0.1", 8443, 0) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_resolve(&config->routes) == QSR_OK);
  const uint32_t versions[] = {QSR_QUIC_V1, QSR_QUIC_V2};
  for (size_t v = 0; v < 2; v++) {
    uint8_t packet[1200];
    protect_initial(packet, versions[v], 0, hello, 0, sizeof(hello));
    save_seed(v == 0 ? "initial/full-v1" : "initial/full-v2", packet, 600);
    protect_initial(packet, versions[v], 0, hello, 0, 40);
    protect_initial(packet + 600, versions[v], 1, hello + 40, 40, 37);
    save_seed(v == 0 ? "initial/v1" : "initial/v2", packet, sizeof(packet));
    qsr_quic_initial_t initial;
    ASSERT_TRUE(qsr_quic_parse_initial(packet, sizeof(packet), &initial) == QSR_OK);
    struct sockaddr_storage source = loopback(40000);
    struct sockaddr_storage backend;
    socklen_t backend_len = 0;
    qsr_pending_initial_t *entry = nullptr;
    qsr_sni_t sni;
    ASSERT_TRUE(route_initial_datagram(config, pending, packet, sizeof(packet), &initial, &source,
                                       sizeof(struct sockaddr_in), 1, &backend, &backend_len, nullptr, &entry,
                                       &sni) == QSR_OK);
    ASSERT_TRUE(strcmp(sni.name, "rvr-a.flightdeck.test") == 0);
    ASSERT_TRUE(entry != nullptr && entry->packet_count == 1 && entry->packet_lens[0] == sizeof(packet));
    ASSERT_TRUE(memcmp(entry->packets[0], packet, sizeof(packet)) == 0);
    pending_initial_remove(pending, entry);
    uint8_t interleaved[1244];
    memcpy(interleaved, packet, 600);
    memcpy(interleaved + 600, packet, 23);
    interleaved[600] = v == 0 ? 0xd0 : 0xe0; /* Opaque 0-RTT between Initials. */
    interleaved[623] = 20;
    memset(interleaved + 624, 0, 20);
    memcpy(interleaved + 644, packet + 600, 600);
    ASSERT_TRUE(route_initial_datagram(config, pending, interleaved, sizeof(interleaved), &initial, &source,
                                       sizeof(struct sockaddr_in), 1, &backend, &backend_len, nullptr, &entry,
                                       &sni) == QSR_OK);
    ASSERT_TRUE(strcmp(sni.name, "rvr-a.flightdeck.test") == 0 && entry->packet_count == 1);
    ASSERT_TRUE(entry->packet_lens[0] == sizeof(interleaved));
    ASSERT_TRUE(memcmp(entry->packets[0], interleaved, sizeof(interleaved)) == 0);
    pending_initial_remove(pending, entry);
  }
  free(config);
  free(pending);
}

static void test_logging_backpressure(void) {
  int fds[2];
  ASSERT_TRUE(pipe2(fds, O_NONBLOCK | O_CLOEXEC) == 0);
  qsr_dataplane_t dp = {.log_started = true, .log_write_fd = fds[1]};
  /* A stopped collector must not stop forwarding or partially write records. */
  for (unsigned i = 0; i < 10000; i++) {
    char line[1024];
    (void)snprintf(line, sizeof(line), "conn: test backpressure record %u\n", i);
    connection_log(&dp, line);
  }
  ASSERT_TRUE(dp.log_drops > 0);
  close(fds[0]);
  close(fds[1]);
}

static void test_descriptor_exhaustion(void) {
  /* Restrict only a child, never the test runner's resource limits. */
  const pid_t child = fork();
  ASSERT_TRUE(child >= 0);
  if (child == 0) {
    qsr_runtime_t *runtime = calloc(1, sizeof(*runtime));
    ASSERT_TRUE(runtime != nullptr && qsr_flow_table_init(&runtime->flows, 4) == QSR_OK);
    qsr_dataplane_t dp = {.runtime = runtime, .epoll_fd = epoll_create1(EPOLL_CLOEXEC)};
    runtime->flows.on_close = conn_close_callback;
    runtime->flows.on_close_userdata = &dp;
    struct sockaddr_storage backend;
    const int receiver = bound_socket(&backend);
    const struct sockaddr_storage client = loopback(40000);
    const qsr_flow_t *flow = flow_acquire(&dp, &client, sizeof(struct sockaddr_in), &backend, sizeof(struct sockaddr_in),
                                   1, nullptr, nullptr, 0);
    ASSERT_TRUE(flow != nullptr);
    const uint8_t packet[] = {0x40, 1, 2, 3};
    sender_enqueue(&dp.sender, flow->fd, packet, sizeof(packet), &backend, sizeof(struct sockaddr_in));
    struct rlimit limit;
    ASSERT_TRUE(getrlimit(RLIMIT_NOFILE, &limit) == 0);
    limit.rlim_cur = 64;
    ASSERT_TRUE(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    int fillers[64];
    size_t count = 0;
    while (count < 64) {
      const int fd = open("/dev/null", O_RDONLY);
      if (fd < 0) {
        break;
      }
      fillers[count++] = fd;
    }
    ASSERT_TRUE(errno == EMFILE);
    const int replacement = flow_socket_open(&runtime->flows, &backend, sizeof(struct sockaddr_in), 0);
    ASSERT_TRUE(replacement >= 0 && runtime->flows.count == 0 && dp.sender.count == 0);
    uint8_t received[32];
    ASSERT_TRUE(recv(receiver, received, sizeof(received), 0) == sizeof(packet));
    ASSERT_TRUE(memcmp(packet, received, sizeof(packet)) == 0);
    for (size_t i = 0; i < count; i++) {
      close(fillers[i]);
    }
    close(replacement);
    close(receiver);
    close(dp.epoll_fd);
    qsr_flow_table_free(&runtime->flows);
    free(runtime);
    _exit(0);
  }
  int status = 0;
  ASSERT_TRUE(waitpid(child, &status, 0) == child);
  ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_ipv6_listener_and_drain(void) {
  struct sockaddr_storage backend;
  int backend_fd = bound_socket(&backend);
  int client_fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_TRUE(client_fd >= 0);
  struct sockaddr_in6 destination = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
  ASSERT_TRUE(bind(client_fd, (struct sockaddr *)&destination, sizeof(destination)) == 0);
  int reservation = socket(AF_INET6, SOCK_DGRAM, 0);
  ASSERT_TRUE(reservation >= 0 && bind(reservation, (struct sockaddr *)&destination, sizeof(destination)) == 0);
  socklen_t len = sizeof(destination);
  ASSERT_TRUE(getsockname(reservation, (struct sockaddr *)&destination, &len) == 0);
  qsr_config_t *config = malloc(sizeof(*config));
  ASSERT_TRUE(config != nullptr);
  qsr_config_default(config);
  config->idle_timeout_seconds = 1;
  config->max_sessions = 1024;
  snprintf(config->listen_udp, sizeof(config->listen_udp), ":%u", ntohs(destination.sin6_port));
  ASSERT_TRUE(qsr_route_table_add(&config->routes, "example.test", "127.0.0.1",
                                   ntohs(((struct sockaddr_in *)&backend)->sin_port), 42) == QSR_OK);
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&config->cid_codec, "00112233445566778899aabbccddeeff") == QSR_OK);
  uint8_t packet[1 + QSR_CID_ENCODED_LEN] = {0x40};
  const uint8_t nonce[QSR_CID_NONCE_LEN] = {1, 2, 3, 4, 5, 6, 7};
  ASSERT_TRUE(qsr_cid_codec_encode(&config->cid_codec, 42, nonce, packet + 1) == QSR_OK);
  close(reservation);
  const pid_t child = fork();
  ASSERT_TRUE(child >= 0);
  if (child == 0) {
    close(client_fd);
    close(backend_fd);
    _exit(qsr_udp_run(config, nullptr) == QSR_OK ? 0 : 1);
  }
  const struct timespec delay = {.tv_nsec = 10000000};
  bool routed = false;
  struct sockaddr_storage upstream = {0};
  uint8_t received[128];
  for (unsigned i = 0; i < 200 && !routed; i++) {
    (void)sendto(client_fd, packet, sizeof(packet), 0, (struct sockaddr *)&destination, sizeof(destination));
    nanosleep(&delay, nullptr);
    len = sizeof(upstream);
    const ssize_t n = recvfrom(backend_fd, received, sizeof(received), 0, (struct sockaddr *)&upstream, &len);
    if (n == sizeof(packet)) {
      routed = memcmp(packet, received, sizeof(packet)) == 0;
    }
  }
  if (routed) {
    (void)sendto(backend_fd, packet, sizeof(packet), 0, (struct sockaddr *)&upstream, len);
    bool replied = false;
    for (unsigned i = 0; i < 100 && !replied; i++) {
      nanosleep(&delay, nullptr);
      replied = recv(client_fd, received, sizeof(received), 0) == sizeof(packet);
    }
    routed = replied;
  }
  (void)kill(child, SIGUSR1);
  (void)kill(child, routed ? SIGUSR2 : SIGTERM);
  int status = 0;
  bool exited = false;
  for (unsigned i = 0; i < 500 && !exited; i++) {
    exited = waitpid(child, &status, WNOHANG) == child;
    if (!exited) {
      nanosleep(&delay, nullptr);
    }
  }
  if (!exited) {
    (void)kill(child, SIGKILL);
    (void)waitpid(child, &status, 0);
  }
  close(client_fd);
  close(backend_fd);
  free(config);
  ASSERT_TRUE(routed && exited && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_quic_lb_routing(void) {
  qsr_runtime_t *runtime = calloc(1, sizeof(*runtime));
  ASSERT_TRUE(runtime != nullptr);
  qsr_config_default(&runtime->config);
  ASSERT_TRUE(qsr_flow_table_init(&runtime->flows, 16) == QSR_OK);
  ASSERT_TRUE(qsr_session_table_init(&runtime->sessions, 1024) == QSR_OK);
  qsr_dataplane_t dp = {.runtime = runtime, .main_fd = -1, .epoll_fd = epoll_create1(EPOLL_CLOEXEC)};
  ASSERT_TRUE(dp.epoll_fd >= 0);
  runtime->flows.on_close = conn_close_callback;
  runtime->flows.on_close_userdata = &dp;
  struct sockaddr_storage backend_a;
  struct sockaddr_storage backend_b;
  const int a = bound_socket(&backend_a);
  const int b = bound_socket(&backend_b);
  ASSERT_TRUE(qsr_route_table_add(&runtime->config.routes, "a.test", "127.0.0.1",
                                   ntohs(((struct sockaddr_in *)&backend_a)->sin_port), 0) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_add(&runtime->config.routes, "b.test", "127.0.0.1",
                                   ntohs(((struct sockaddr_in *)&backend_b)->sin_port), 0) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_resolve(&runtime->config.routes) == QSR_OK);
  qsr_cid_codec_t key;
  ASSERT_TRUE(qsr_cid_codec_init_from_hex(&key, "8f95f09245765f80256934e50c66207f") == QSR_OK);
  ASSERT_TRUE(qsr_quic_lb_config_init(&runtime->config.quic_lb, 0, 3, 4, key.key) == QSR_OK);
  ASSERT_TRUE(qsr_quic_lb_config_init(&runtime->config.quic_lb, 1, 3, 4, nullptr) == QSR_OK);
  const qsr_quic_lb_server_id_t id_a = {.bytes = {0xed, 0x79, 0x3a}, .len = 3};
  const qsr_quic_lb_server_id_t id_b = {.len = 3};
  ASSERT_TRUE(qsr_route_table_set_quic_lb_id(&runtime->config.routes, 0, 0, &id_a) == QSR_OK);
  ASSERT_TRUE(qsr_route_table_set_quic_lb_id(&runtime->config.routes, 1, 1, &id_b) == QSR_OK);
  const uint8_t packet_a[] = {0x40, 0x07, 0x20, 0xb1, 0xd0, 0x7b, 0x35, 0x9d, 0x3c, 0xaa};
  /* No backend CID learning or ClientHello was involved. Rebinding must route
   * from the encrypted CID alone, preserving the original datagram. */
  uint8_t received[64];
  for (unsigned port = 40000; port <= 40001; port++) {
    const struct sockaddr_storage client = loopback(port);
    handle_client_packet(&dp, packet_a, sizeof(packet_a), &client, sizeof(struct sockaddr_in), 1);
    sender_flush(&dp.sender);
    ASSERT_TRUE(recv(a, received, sizeof(received), 0) == sizeof(packet_a));
    ASSERT_TRUE(memcmp(packet_a, received, sizeof(packet_a)) == 0);
  }
  const struct sockaddr_storage client = loopback(40000);
  /* Same tuple, another active configuration: CID routing must beat cached
   * flow/tuple state. Low first-octet bits and QUIC's fixed bit are not gates. */
  const uint8_t packet_b[] = {0x00, 0x3f, 0, 0, 0, 1, 2, 3, 4, 0xbb};
  handle_client_packet(&dp, packet_b, sizeof(packet_b), &client, sizeof(struct sockaddr_in), 2);
  sender_flush(&dp.sender);
  ASSERT_TRUE(recv(b, received, sizeof(received), 0) == sizeof(packet_b));
  ASSERT_TRUE(memcmp(packet_b, received, sizeof(packet_b)) == 0);
  /* Long-header extraction is version independent; SCID length follows DCID. */
  uint8_t long_packet[15] = {0x80, 0xaa, 0xbb, 0xcc, 0xdd, 8};
  memcpy(long_packet + 6, packet_a + 1, 8);
  handle_client_packet(&dp, long_packet, sizeof(long_packet), &client, sizeof(struct sockaddr_in), 3);
  sender_flush(&dp.sender);
  ASSERT_TRUE(recv(a, received, sizeof(received), 0) == sizeof(long_packet));
  ASSERT_TRUE(memcmp(long_packet, received, sizeof(long_packet)) == 0);

  qsr_session_key_t tuple = qsr_session_tuple_key(&client, sizeof(struct sockaddr_in));
  long_packet[5] = 7; /* Explicit DCID length, not bytes of SCID/payload. */
  ASSERT_TRUE(lookup_encoded_cid(&runtime->config, &runtime->sessions, long_packet, sizeof(long_packet), &tuple, 4) == nullptr);
  uint8_t unknown[10];
  memcpy(unknown, packet_b, sizeof(unknown));
  unknown[1] = 0xe0;
  ASSERT_TRUE(lookup_encoded_cid(&runtime->config, &runtime->sessions, unknown, sizeof(unknown), &tuple, 4) == nullptr);
  unknown[1] = 0x40;
  ASSERT_TRUE(lookup_encoded_cid(&runtime->config, &runtime->sessions, unknown, sizeof(unknown), &tuple, 4) == nullptr);
  unknown[1] = 0x20;
  unknown[2] = 1;
  ASSERT_TRUE(lookup_encoded_cid(&runtime->config, &runtime->sessions, unknown, sizeof(unknown), &tuple, 4) == nullptr);
  /* One valid-size seed per decoder branch; ciphertext need not authenticate. */
  for (unsigned rotation = 0; rotation < 7; rotation++) {
    uint8_t seed[20] = {0};
    seed[0] = (uint8_t)(rotation << 5U);
    char name[32];
    (void)snprintf(name, sizeof(name), "quic_lb/config-%u", rotation);
    save_seed(name, seed, sizeof(seed));
  }
  qsr_flow_table_free(&runtime->flows);
  qsr_session_table_free(&runtime->sessions);
  close(a);
  close(b);
  close(dp.epoll_fd);
  free(runtime);
}

int main(int argc, char **argv) {
  seed_directory = argc == 2 ? argv[1] : nullptr;
  test_socket_marks();
  test_flow_lifetimes_and_sources();
  test_pressure_eviction();
  test_gro_and_gso();
  test_listen_addresses();
  test_reply_source_address();
  test_completed_reload();
  test_kubernetes_symlink_reload();
  test_coalesced_initials();
  test_logging_backpressure();
  test_descriptor_exhaustion();
  test_ipv6_listener_and_drain();
  test_quic_lb_routing();
  return 0;
}
