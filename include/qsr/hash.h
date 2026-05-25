/*
 * qsr/hash.h — keyed hash with a per-process random key, used by the session
 * and route tables.
 *
 * Why keyed: open-addressed hash tables fed attacker-controlled bytes (QUIC
 * Destination Connection IDs land in the session table; SNIs land in the
 * route table) are trivially DoS-able with unkeyed hashes like FNV-1a — an
 * attacker who knows the hash function can craft inputs that collide on the
 * same bucket and force O(N) probe walks. SipHash-2-4 with a 16-byte key
 * picked from getrandom() at process start makes collision-forcing
 * cryptographically infeasible.
 *
 * The bare qsr_siphash24 entry point is exposed for unit tests that pin the
 * implementation against the published RFC test vectors; production code
 * should call qsr_hash_bytes which uses the process-wide random key.
 */
#ifndef QSR_HASH_H
#define QSR_HASH_H

#include "qsr/common.h"

/*
 * SipHash-2-4 over `data` of length `len` with the 16-byte `key`. Returns the
 * 64-bit MAC as a uint64_t (host byte order). Deterministic and side-effect
 * free.
 */
[[nodiscard]] uint64_t qsr_siphash24(const uint8_t *data, size_t len, const uint8_t key[16]);

/*
 * Seed the process-wide hash key from getrandom(). Idempotent and safe to
 * call more than once (re-seeds). Returns QSR_OK on success; QSR_ERR_INVALID
 * if getrandom is unavailable / fails (extremely rare on a healthy Linux).
 *
 * SHOULD be called from main() before any code that hashes attacker-
 * controlled input. qsr_hash_bytes performs a lazy seed on first use as a
 * safety net for callers (notably unit tests) that forget.
 */
[[nodiscard]] qsr_status_t qsr_hash_init(void);

/*
 * SipHash-2-4 over (data, len) using the process-wide random key. Same
 * output for the same input within a process; uncorrelated across processes.
 */
[[nodiscard]] uint64_t qsr_hash_bytes(const void *data, size_t len);

#endif
