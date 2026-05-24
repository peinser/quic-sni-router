#include "qsr/tls_client_hello.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  qsr_sni_t sni;
  (void)qsr_tls_client_hello_sni(data, size, &sni);
  return 0;
}
