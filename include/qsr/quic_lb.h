#ifndef QSR_QUIC_LB_H
#define QSR_QUIC_LB_H

#include "qsr/common.h"

/* Wire format pinned to draft-ietf-quic-load-balancers-21, sections 3 and 5.
 * Unlike the qsr HMAC codec, QUIC-LB encrypts but does NOT authenticate CIDs. */
#define QSR_QUIC_LB_CONFIGS 7U
#define QSR_QUIC_LB_MAX_SERVER_ID 15U

typedef struct qsr_quic_lb_server_id {
  uint8_t bytes[QSR_QUIC_LB_MAX_SERVER_ID];
  uint8_t len; /* Zero means absent; an all-zero, nonempty ID is valid. */
} qsr_quic_lb_server_id_t;

typedef struct qsr_quic_lb_config {
  bool active;
  bool encrypted;
  uint8_t server_id_len;
  uint8_t nonce_len;
  uint8_t key[16];
} qsr_quic_lb_config_t;

typedef struct qsr_quic_lb {
  bool enabled;
  qsr_quic_lb_config_t configs[QSR_QUIC_LB_CONFIGS];
} qsr_quic_lb_t;

/* Start with a zero-initialized qsr_quic_lb_t; duplicate slots are rejected.
 * Validate at configuration time, not on each packet. A null key selects the
 * draft's unencrypted format. Config codepoint 7 is always unroutable. */
[[nodiscard]] qsr_status_t qsr_quic_lb_config_init(qsr_quic_lb_t *lb, uint8_t id, uint8_t server_id_len,
                                                  uint8_t nonce_len, const uint8_t *key);
/* cid_len is the long-header DCID length, or available short-header bytes
 * capped at 20. Extra CID bytes and the first octet's low five bits are ignored. */
[[nodiscard]] qsr_status_t qsr_quic_lb_decode(const qsr_quic_lb_t *lb, const uint8_t *cid, size_t cid_len,
                                             uint8_t *config_id, qsr_quic_lb_server_id_t *server_id);

#endif
