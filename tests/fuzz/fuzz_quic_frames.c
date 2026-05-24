#include "qsr/quic_frames.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  qsr_crypto_stream_t stream;
  qsr_crypto_stream_init(&stream);
  (void)qsr_quic_extract_crypto(data, size, &stream);
  return 0;
}
