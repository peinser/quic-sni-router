#include "qsr/tls_client_hello.h"
#include "test_main.h"

#include <string.h>

static void test_extracts_sni(void) {
  const uint8_t hello[] = {
      0x01, 0x00, 0x00, 0x49, 0x03, 0x03,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x1e,
      0x00, 0x00, 0x00, 0x1a, 0x00, 0x18, 0x00, 0x00,
      0x15, 'r',  'v',  'r',  '-',  'a',  '.',  'f',
      'l',  'i',  'g',  'h',  't',  'd',  'e',  'c',
      'k',  '.',  't',  'e',  's',  't'};
  qsr_sni_t sni;
  ASSERT_TRUE(qsr_tls_client_hello_sni(hello, sizeof(hello), &sni) == QSR_OK);
  ASSERT_TRUE(sni.name[0] == 'r');
}

static void test_rejects_oversize(void) {
  static uint8_t too_large[QSR_MAX_CLIENT_HELLO_SIZE + 1U] = {0};
  qsr_sni_t sni;
  ASSERT_TRUE(qsr_tls_client_hello_sni(too_large, sizeof(too_large), &sni) == QSR_ERR_INVALID);
}

static void test_rejects_truncated(void) {
  /* Handshake type byte present + start of uint24 length, no body — the
   * reader should detect this as truncated rather than invalid. */
  const uint8_t truncated[] = {0x01, 0x00, 0x00};
  qsr_sni_t sni;
  ASSERT_TRUE(qsr_tls_client_hello_sni(truncated, sizeof(truncated), &sni) == QSR_ERR_TRUNCATED);
}

/*
 * The wrong handshake message type (0x02 server_hello here) is INVALID,
 * not TRUNCATED — the bytes are present, they just don't say "client_hello".
 * This is the test the previous flat parser implicitly covered by the
 * upfront `42U > len - offset` check; the restructured reader separates
 * the two failure modes cleanly.
 */
static void test_rejects_wrong_handshake_type(void) {
  uint8_t buf[80] = {0};
  buf[0] = 0x02;  /* server_hello, not client_hello */
  qsr_sni_t sni;
  ASSERT_TRUE(qsr_tls_client_hello_sni(buf, sizeof(buf), &sni) == QSR_ERR_INVALID);
}

static void test_rejects_invalid_hostname(void) {
  /*
   * Same ClientHello as above but the SNI value contains a slash, which the
   * router rejects to keep route lookups well-defined.
   */
  const uint8_t hello[] = {
      0x01, 0x00, 0x00, 0x49, 0x03, 0x03,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x1e,
      0x00, 0x00, 0x00, 0x1a, 0x00, 0x18, 0x00, 0x00,
      0x15, 'r',  'v',  'r',  '-',  '/',  '.',  'f',
      'l',  'i',  'g',  'h',  't',  'd',  'e',  'c',
      'k',  '.',  't',  'e',  's',  't'};
  qsr_sni_t sni;
  ASSERT_TRUE(qsr_tls_client_hello_sni(hello, sizeof(hello), &sni) == QSR_ERR_INVALID);
}

void test_tls_client_hello(void) {
  test_extracts_sni();
  test_rejects_oversize();
  test_rejects_truncated();
  test_rejects_wrong_handshake_type();
  test_rejects_invalid_hostname();
}
