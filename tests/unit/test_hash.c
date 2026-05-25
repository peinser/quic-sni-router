#include "qsr/hash.h"
#include "test_main.h"

#include <string.h>

/*
 * Reference test vectors from the SipHash paper (Aumasson & Bernstein 2012).
 * The published vectors use key = 00 01 02 .. 0f and message bytes 00, 01,
 * ..., n-1 for n = 0..63. The 8-byte output is little-endian; the
 * qsr_siphash24 entry point returns it as a uint64_t in host byte order, so
 * we read the published bytes back as a little-endian uint64.
 */
static const uint8_t SIPHASH_KEY[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

/* First 8 vectors from the reference suite. Each line is the expected output
 * for message {0x00, 0x01, ..., n-1} where n is the line index. */
static const uint64_t SIPHASH_EXPECTED[8] = {
    UINT64_C(0x726fdb47dd0e0e31),  /* n=0, empty message */
    UINT64_C(0x74f839c593dc67fd),  /* n=1 */
    UINT64_C(0x0d6c8009d9a94f5a),  /* n=2 */
    UINT64_C(0x85676696d7fb7e2d),  /* n=3 */
    UINT64_C(0xcf2794e0277187b7),  /* n=4 */
    UINT64_C(0x18765564cd99a68d),  /* n=5 */
    UINT64_C(0xcbc9466e58fee3ce),  /* n=6 */
    UINT64_C(0xab0200f58b01d137),  /* n=7 */
};

static void test_rfc_vectors(void) {
  uint8_t msg[8];
  for (size_t n = 0; n < 8; n++) {
    for (size_t i = 0; i < n; i++) {
      msg[i] = (uint8_t)i;
    }
    const uint64_t got = qsr_siphash24(msg, n, SIPHASH_KEY);
    if (got != SIPHASH_EXPECTED[n]) {
      fprintf(stderr, "siphash mismatch at n=%zu: got %016llx expected %016llx\n", n,
              (unsigned long long)got, (unsigned long long)SIPHASH_EXPECTED[n]);
    }
    ASSERT_TRUE(got == SIPHASH_EXPECTED[n]);
  }
}

static void test_deterministic_within_process(void) {
  ASSERT_TRUE(qsr_hash_init() == QSR_OK);
  const uint8_t msg[] = "the quick brown fox jumps over the lazy dog";
  const uint64_t a = qsr_hash_bytes(msg, sizeof(msg) - 1);
  const uint64_t b = qsr_hash_bytes(msg, sizeof(msg) - 1);
  ASSERT_TRUE(a == b);
}

/*
 * Re-seeding must change the output for the same input, otherwise hash
 * flooding is still trivial (attacker brute-forces the one key once and
 * keeps replaying). One per-process random key is meaningless if the key
 * is constant across runs.
 */
static void test_reseed_changes_output(void) {
  const uint8_t msg[] = "victim-input";
  ASSERT_TRUE(qsr_hash_init() == QSR_OK);
  const uint64_t a = qsr_hash_bytes(msg, sizeof(msg) - 1);
  ASSERT_TRUE(qsr_hash_init() == QSR_OK);
  const uint64_t b = qsr_hash_bytes(msg, sizeof(msg) - 1);
  /*
   * 64-bit random keys: collision probability per pair is 2^-64. If this
   * test ever fires it's overwhelmingly more likely that the re-seed is
   * broken than that we hit the birthday lottery.
   */
  ASSERT_TRUE(a != b);
}

static void test_different_inputs_differ(void) {
  ASSERT_TRUE(qsr_hash_init() == QSR_OK);
  const uint64_t a = qsr_hash_bytes("a", 1);
  const uint64_t b = qsr_hash_bytes("b", 1);
  ASSERT_TRUE(a != b);
}

/*
 * Empty input is a legal SipHash input. Verify it doesn't crash and produces
 * something deterministic for a fixed key.
 */
static void test_empty_input(void) {
  ASSERT_TRUE(qsr_hash_init() == QSR_OK);
  const uint64_t a = qsr_hash_bytes("", 0);
  const uint64_t b = qsr_hash_bytes("", 0);
  ASSERT_TRUE(a == b);
}

/*
 * Distribution sanity: hashing 4096 distinct 8-byte inputs into 256 buckets
 * should produce something close to uniform. We assert every bucket is
 * non-empty (probability of any bucket being empty for 4096 trials over 256
 * buckets is ~(255/256)^4096 = ~1e-7 per bucket; for any of 256 buckets
 * ~6e-5 — small enough to not be flaky in CI).
 */
static void test_distribution(void) {
  ASSERT_TRUE(qsr_hash_init() == QSR_OK);
  unsigned counts[256] = {0};
  for (uint32_t i = 0; i < 4096; i++) {
    uint8_t buf[8];
    for (int j = 0; j < 8; j++) {
      buf[j] = (uint8_t)(i >> (j * 4));
    }
    counts[qsr_hash_bytes(buf, sizeof(buf)) & 0xffU]++;
  }
  size_t empty = 0;
  for (int i = 0; i < 256; i++) {
    if (counts[i] == 0U) {
      empty++;
    }
  }
  ASSERT_TRUE(empty == 0U);
}

void test_hash(void) {
  test_rfc_vectors();
  test_deterministic_within_process();
  test_reseed_changes_output();
  test_different_inputs_differ();
  test_empty_input();
  test_distribution();
}
