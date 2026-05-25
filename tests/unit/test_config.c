#include "qsr/config.h"
#include "test_main.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void write_temp(const char *content, char path[]) {
  const int fd = mkstemp(path);
  ASSERT_TRUE(fd >= 0);
  FILE *file = fdopen(fd, "w");
  ASSERT_TRUE(file != nullptr);
  ASSERT_TRUE(fputs(content, file) >= 0);
  ASSERT_TRUE(fclose(file) == 0);
}

static void load_and_unlink(const char *content, qsr_config_t *config, qsr_status_t expected) {
  char path[] = "/tmp/qsr-cfg-XXXXXX";
  write_temp(content, path);
  ASSERT_TRUE(qsr_config_load(path, config) == expected);
  ASSERT_TRUE(unlink(path) == 0);
}

static void test_defaults(void) {
  qsr_config_t config;
  qsr_config_default(&config);
  ASSERT_TRUE(config.idle_timeout_seconds == 60U);
  ASSERT_TRUE(config.max_sessions == QSR_MAX_SESSIONS_DEFAULT);
  ASSERT_TRUE(strcmp(config.listen_udp, ":443") == 0);
}

static void test_loads_full_config(void) {
  qsr_config_t config;
  load_and_unlink(
      "listen:\n  udp: \":443\"\n"
      "sessions:\n  idleTimeout: 60s\n  maxSessions: 10\n"
      "routes:\n  RVR-A.flightdeck.test:\n    host: 127.0.0.1\n    port: 8443\n",
      &config, QSR_OK);
  ASSERT_TRUE(config.routes.count == 1U);
  ASSERT_TRUE(qsr_route_table_lookup(&config.routes, "rvr-a.flightdeck.test") != nullptr);
  ASSERT_TRUE(config.max_sessions == 10U);
}

static void test_empty_file_yields_defaults(void) {
  qsr_config_t config;
  load_and_unlink("", &config, QSR_OK);
  ASSERT_TRUE(config.idle_timeout_seconds == 60U);
  ASSERT_TRUE(config.routes.count == 0U);
}

static void test_rejects_bad_integer(void) {
  qsr_config_t config;
  load_and_unlink("sessions:\n  idleTimeout: nope\n", &config, QSR_ERR_INVALID);
}

static void test_rejects_unknown_top_level_key(void) {
  qsr_config_t config;
  /*
   * Strict-by-default: an unknown top-level key (e.g. a typo) is a config error
   * rather than a silent no-op. The hand-rolled parser also rejected this; the
   * libyaml-backed parser preserves the contract.
   */
  load_and_unlink("listen:\n  udp: \":443\"\nbogus: 1\n", &config, QSR_ERR_INVALID);
}

static void test_rejects_unknown_route_field(void) {
  qsr_config_t config;
  load_and_unlink(
      "routes:\n  a.example.test:\n    host: 127.0.0.1\n    port: 8443\n    weight: 100\n",
      &config, QSR_ERR_INVALID);
}

static void test_rejects_route_missing_port(void) {
  qsr_config_t config;
  load_and_unlink("routes:\n  a.example.test:\n    host: 127.0.0.1\n", &config, QSR_ERR_INVALID);
}

static void test_accepts_comments_and_inline_quotes(void) {
  qsr_config_t config;
  /*
   * The hand-rolled parser stripped '#' naively, mishandling inline comments
   * after quoted values and any quoted scalar containing a '#'. libyaml does
   * this correctly per YAML 1.1.
   */
  load_and_unlink(
      "# leading full-line comment\n"
      "listen:\n"
      "  udp: \":443\"  # inline comment after quoted scalar\n"
      "routes:\n"
      "  a.example.test:\n"
      "    host: \"127.0.0.1\"  # quoted host, inline comment\n"
      "    port: 8443\n",
      &config, QSR_OK);
  ASSERT_TRUE(config.routes.count == 1U);
  ASSERT_TRUE(qsr_route_table_lookup(&config.routes, "a.example.test") != nullptr);
}

static void test_accepts_flow_style(void) {
  qsr_config_t config;
  /* libyaml accepts JSON-compatible flow style; the schema doesn't care. */
  load_and_unlink(
      "{ listen: { udp: \":443\" }, routes: { a.example.test: { host: 127.0.0.1, port: 8443 } } }\n",
      &config, QSR_OK);
  ASSERT_TRUE(config.routes.count == 1U);
  ASSERT_TRUE(qsr_route_table_lookup(&config.routes, "a.example.test") != nullptr);
}

static void test_accepts_anchors_and_aliases(void) {
  qsr_config_t config;
  load_and_unlink(
      "routes:\n"
      "  a.example.test: &backend\n"
      "    host: 127.0.0.1\n"
      "    port: 8443\n"
      "  b.example.test: *backend\n",
      &config, QSR_OK);
  ASSERT_TRUE(config.routes.count == 2U);
  ASSERT_TRUE(qsr_route_table_lookup(&config.routes, "a.example.test") != nullptr);
  ASSERT_TRUE(qsr_route_table_lookup(&config.routes, "b.example.test") != nullptr);
}

static void test_rejects_malformed_yaml(void) {
  qsr_config_t config;
  load_and_unlink("listen:\n  udp: \"unclosed\n", &config, QSR_ERR_INVALID);
}

void test_config(void);
void test_quic_initial(void);
void test_quic_frames(void);
void test_quic_crypto(void);
void test_tls_client_hello(void);
void test_route_table(void);
void test_session_table(void);
void test_hash(void);

void test_config(void) {
  test_defaults();
  test_loads_full_config();
  test_empty_file_yields_defaults();
  test_rejects_bad_integer();
  test_rejects_unknown_top_level_key();
  test_rejects_unknown_route_field();
  test_rejects_route_missing_port();
  test_accepts_comments_and_inline_quotes();
  test_accepts_flow_style();
  test_accepts_anchors_and_aliases();
  test_rejects_malformed_yaml();
}

int main(void) {
  test_hash();
  test_config();
  test_quic_initial();
  test_quic_frames();
  test_quic_crypto();
  test_tls_client_hello();
  test_route_table();
  test_session_table();
  return 0;
}
