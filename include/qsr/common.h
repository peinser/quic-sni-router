/*
 * qsr/common.h: shared types, limits, and status codes used across the
 * router. Every other public header in qsr/ pulls this in for the qsr_status_t
 * enum and the QSR_* size constants. No code here.
 */
#ifndef QSR_COMMON_H
#define QSR_COMMON_H

#include <stddef.h>
#include <stdint.h>

#if __STDC_VERSION__ < 202311L
#include <stdbool.h>
#endif

/*
 * Limits are kept as #defines so they remain usable as array dimensions in
 * any compilation mode. C23 constexpr-for-objects would be cleaner but is
 * not yet uniformly available across toolchains we target (Clang 18 lacks it).
 */
#define QSR_MAX_DATAGRAM_SIZE 1500U
#define QSR_MAX_CLIENT_HELLO_SIZE 8192U
#define QSR_MAX_ROUTES 1024U
#define QSR_ROUTE_BUCKETS 2048U
#define QSR_MAX_SESSIONS_DEFAULT 100000U
#define QSR_MAX_HOSTNAME_LEN 255U
#define QSR_MAX_ADDR_LEN 255U
#define QSR_MAX_LISTEN_ADDR_LEN 64U
#define QSR_MAX_QUIC_CID_LEN 20U
#define QSR_QUIC_V1 0x00000001U
/* RFC 9369 (QUIC v2). Uses a different Initial salt, different HKDF labels
 * ("quicv2 key/iv/hp"), and rotates the long-header type bits (Initial=0b01,
 * 0-RTT=0b10, Handshake=0b11, Retry=0b00). Everything else (header layout,
 * varints, AES-128-GCM, AES-128-ECB header protection) is identical to v1. */
#define QSR_QUIC_V2 0x6b3343cfU

/*
 * RFC 9000 §14.1: clients MUST pad UDP datagrams carrying an Initial packet
 * to at least 1200 bytes. Anything smaller from a previously-unknown source
 * is dropped to avoid serving as a cheap reflection/amplification target.
 */
#define QSR_MIN_INITIAL_DATAGRAM_SIZE 1200U

/*
 * Stricter floor on the protected Initial payload: 4-byte assumed packet
 * number window + 16-byte AES-GCM tag + at least 16 bytes for the AES-ECB
 * header-protection sample. Reject anything shorter rather than feeding it
 * to OpenSSL.
 */
#define QSR_MIN_INITIAL_PAYLOAD_LEN 36U

typedef enum qsr_status {
  QSR_OK = 0,
  QSR_ERR_INVALID = -1,
  QSR_ERR_TRUNCATED = -2,
  QSR_ERR_UNSUPPORTED = -3,
  QSR_ERR_NOT_FOUND = -4,
  QSR_ERR_FULL = -5,
} qsr_status_t;

#endif
