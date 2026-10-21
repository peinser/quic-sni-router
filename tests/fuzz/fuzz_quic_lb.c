#include "qsr/quic_lb.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  qsr_quic_lb_t lb = {0};
  const uint8_t key[16] = {0};
  const uint8_t sid_lengths[] = {3, 10, 8, 9, 15, 1, 15};
  const uint8_t nonce_lengths[] = {4, 5, 8, 9, 4, 4, 4};
  for (uint8_t i = 0; i < QSR_QUIC_LB_CONFIGS; i++) {
    if (qsr_quic_lb_config_init(&lb, i, sid_lengths[i], nonce_lengths[i], i < 5 ? key : nullptr) != QSR_OK) {
      return 0;
    }
  }
  uint8_t rotation;
  qsr_quic_lb_server_id_t server_id;
  (void)qsr_quic_lb_decode(&lb, data, size, &rotation, &server_id);
  return 0;
}
