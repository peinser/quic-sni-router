#include "qsr/quic_frames.h"
#include "test_main.h"

#include <string.h>

static void test_extract_simple_crypto(void) {
  const uint8_t crypto[] = {0x06, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'};
  qsr_crypto_stream_t stream;
  qsr_crypto_stream_init(&stream);
  ASSERT_TRUE(qsr_quic_extract_crypto(crypto, sizeof(crypto), &stream) == QSR_OK);
  ASSERT_TRUE(stream.len == 5U);
  ASSERT_TRUE(memcmp(stream.data, "hello", 5U) == 0);
}

static void test_extract_split_crypto(void) {
  /* Two CRYPTO frames in non-sorted order are reassembled correctly. */
  const uint8_t split[] = {0x06, 0x02, 0x03, 'l', 'l', 'o', 0x06, 0x00, 0x02, 'h', 'e'};
  qsr_crypto_stream_t stream;
  qsr_crypto_stream_init(&stream);
  ASSERT_TRUE(qsr_quic_extract_crypto(split, sizeof(split), &stream) == QSR_OK);
  ASSERT_TRUE(stream.len == 5U);
  ASSERT_TRUE(memcmp(stream.data, "hello", 5U) == 0);
}

static void test_extract_skips_padding_ping(void) {
  /* PADDING and PING frames are ignored, then CRYPTO is parsed. */
  const uint8_t frames[] = {0x00, 0x00, 0x01, 0x06, 0x00, 0x03, 'h', 'i', '!'};
  qsr_crypto_stream_t stream;
  qsr_crypto_stream_init(&stream);
  ASSERT_TRUE(qsr_quic_extract_crypto(frames, sizeof(frames), &stream) == QSR_OK);
  ASSERT_TRUE(stream.len == 3U);
  ASSERT_TRUE(memcmp(stream.data, "hi!", 3U) == 0);
}

static void test_extract_skips_ack(void) {
  /*
   * ACK frame followed by CRYPTO. ACK fields (largest=2, delay=0,
   * range_count=0, first_range=0) are all 1-byte varints.
   */
  const uint8_t frames[] = {0x02, 0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 'o', 'k'};
  qsr_crypto_stream_t stream;
  qsr_crypto_stream_init(&stream);
  ASSERT_TRUE(qsr_quic_extract_crypto(frames, sizeof(frames), &stream) == QSR_OK);
  ASSERT_TRUE(stream.len == 2U);
  ASSERT_TRUE(memcmp(stream.data, "ok", 2U) == 0);
}

static void test_extract_rejects_unknown_frame(void) {
  /* STREAM (0x08) is not legal in Initial space and is rejected. */
  const uint8_t unsupported[] = {0x08};
  qsr_crypto_stream_t stream;
  qsr_crypto_stream_init(&stream);
  ASSERT_TRUE(qsr_quic_extract_crypto(unsupported, sizeof(unsupported), &stream) == QSR_ERR_UNSUPPORTED);
}

static void test_extract_rejects_truncated_crypto(void) {
  const uint8_t truncated[] = {0x06, 0x00, 0x05, 'h'};
  qsr_crypto_stream_t stream;
  qsr_crypto_stream_init(&stream);
  ASSERT_TRUE(qsr_quic_extract_crypto(truncated, sizeof(truncated), &stream) == QSR_ERR_INVALID);
}

static void test_extract_rejects_oversize_input(void) {
  /* Buffer larger than the maximum legal ClientHello reassembly window. */
  static uint8_t huge[QSR_MAX_CLIENT_HELLO_SIZE + 1U] = {0};
  qsr_crypto_stream_t stream;
  qsr_crypto_stream_init(&stream);
  ASSERT_TRUE(qsr_quic_extract_crypto(huge, sizeof(huge), &stream) == QSR_ERR_INVALID);
}

void test_quic_frames(void) {
  test_extract_simple_crypto();
  test_extract_split_crypto();
  test_extract_skips_padding_ping();
  test_extract_skips_ack();
  test_extract_rejects_unknown_frame();
  test_extract_rejects_truncated_crypto();
  test_extract_rejects_oversize_input();
}
