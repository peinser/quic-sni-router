/*
 * SipHash-2-4 implementation adapted from the reference code by Jean-Philippe
 * Aumasson and Daniel J. Bernstein (https://github.com/veorq/SipHash), placed
 * in the public domain under CC0. Only the function shape, error handling,
 * and the lazy-init wrapper are local.
 */
#include "qsr/hash.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64U - (b))))

#define U8TO64_LE(p)                                                                                                  \
  (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8U) | ((uint64_t)((p)[2]) << 16U) | ((uint64_t)((p)[3]) << 24U) |    \
   ((uint64_t)((p)[4]) << 32U) | ((uint64_t)((p)[5]) << 40U) | ((uint64_t)((p)[6]) << 48U) |                          \
   ((uint64_t)((p)[7]) << 56U))

#define SIPROUND                                                                                                      \
  do {                                                                                                                \
    v0 += v1;                                                                                                         \
    v1 = ROTL(v1, 13U);                                                                                               \
    v1 ^= v0;                                                                                                         \
    v0 = ROTL(v0, 32U);                                                                                               \
    v2 += v3;                                                                                                         \
    v3 = ROTL(v3, 16U);                                                                                               \
    v3 ^= v2;                                                                                                         \
    v0 += v3;                                                                                                         \
    v3 = ROTL(v3, 21U);                                                                                               \
    v3 ^= v0;                                                                                                         \
    v2 += v1;                                                                                                         \
    v1 = ROTL(v1, 17U);                                                                                               \
    v1 ^= v2;                                                                                                         \
    v2 = ROTL(v2, 32U);                                                                                               \
  } while (0)

uint64_t qsr_siphash24(const uint8_t *data, size_t len, const uint8_t key[16]) {
  const uint64_t k0 = U8TO64_LE(key);
  const uint64_t k1 = U8TO64_LE(key + 8);
  uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
  uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
  uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
  uint64_t v3 = 0x7465646279746573ULL ^ k1;

  const size_t left = len & 7U;
  const uint8_t *const end = data + len - left;
  uint64_t b = ((uint64_t)len) << 56U;

  for (; data != end; data += 8) {
    const uint64_t m = U8TO64_LE(data);
    v3 ^= m;
    SIPROUND;
    SIPROUND;
    v0 ^= m;
  }

  /*
   * The trailing-byte switch is the canonical SipHash idiom. `[[fallthrough]]`
   * is the C23 attribute equivalent of GCC's __attribute__((fallthrough)).
   */
  switch (left) {
    case 7:
      b |= ((uint64_t)data[6]) << 48U;
      [[fallthrough]];
    case 6:
      b |= ((uint64_t)data[5]) << 40U;
      [[fallthrough]];
    case 5:
      b |= ((uint64_t)data[4]) << 32U;
      [[fallthrough]];
    case 4:
      b |= ((uint64_t)data[3]) << 24U;
      [[fallthrough]];
    case 3:
      b |= ((uint64_t)data[2]) << 16U;
      [[fallthrough]];
    case 2:
      b |= ((uint64_t)data[1]) << 8U;
      [[fallthrough]];
    case 1:
      b |= ((uint64_t)data[0]);
      break;
    case 0:
    default:
      break;
  }

  v3 ^= b;
  SIPROUND;
  SIPROUND;
  v0 ^= b;
  v2 ^= 0xffU;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  return v0 ^ v1 ^ v2 ^ v3;
}

#undef ROTL
#undef U8TO64_LE
#undef SIPROUND

/*
 * Process-wide random key. Single-threaded dataplane, so no atomics needed;
 * the first call to qsr_hash_bytes lazily seeds if main() forgot.
 */
static uint8_t g_hash_key[16] = {0};
static bool g_hash_key_seeded = false;

qsr_status_t qsr_hash_init(void) {
  /*
   * getrandom(2) with flags=0 reads from /dev/urandom and blocks at most
   * until the kernel pool is initialized (essentially instant after boot
   * on any non-pathological system). We treat partial reads as failure —
   * a 16-byte read either fully succeeds or we refuse to start hashing.
   */
  uint8_t buf[16];
  ssize_t n = 0;
  while (n < (ssize_t)sizeof(buf)) {
    const ssize_t got = getrandom(buf + n, sizeof(buf) - (size_t)n, 0);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      (void)fprintf(stderr, "qsr_hash_init: getrandom: %s\n", strerror(errno));
      return QSR_ERR_INVALID;
    }
    n += got;
  }
  memcpy(g_hash_key, buf, sizeof(g_hash_key));
  g_hash_key_seeded = true;
  return QSR_OK;
}

uint64_t qsr_hash_bytes(const void *data, size_t len) {
  if (!g_hash_key_seeded) {
    /*
     * Lazy seeding: a missed startup init shouldn't silently fall back to a
     * constant or all-zero key (which would re-introduce the hash-flooding
     * vector we're defending against). If getrandom outright fails (only
     * realistically possible on a fundamentally broken kernel — Linux's
     * urandom pool is initialized before init starts), there's no safe
     * fallback for an open-addressed-table hash. Fail hard rather than
     * silently degrade.
     */
    if (qsr_hash_init() != QSR_OK) {
      (void)fprintf(stderr, "qsr_hash_bytes: cannot seed SipHash key; aborting\n");
      abort();
    }
  }
  return qsr_siphash24((const uint8_t *)data, len, g_hash_key);
}
