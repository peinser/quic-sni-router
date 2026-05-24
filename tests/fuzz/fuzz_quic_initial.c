#include "qsr/quic_crypto.h"
#include "qsr/quic_frames.h"
#include "qsr/quic_initial.h"
#include "qsr/tls_client_hello.h"

/*
 * Drive the full parse -> decrypt -> extract crypto -> parse ClientHello
 * pipeline. Even a fuzzer-generated input that fails AEAD authentication
 * must not crash. Decryption failure short-circuits the rest, which is
 * exactly the production behavior we want to verify.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  qsr_quic_initial_t initial;
  if (qsr_quic_parse_initial(data, size, &initial) != QSR_OK) {
    return 0;
  }
  qsr_quic_plaintext_t plaintext;
  if (qsr_quic_decrypt_initial(data, size, &initial, &plaintext) != QSR_OK) {
    return 0;
  }
  qsr_crypto_stream_t stream;
  qsr_crypto_stream_init(&stream);
  if (qsr_quic_extract_crypto(plaintext.data, plaintext.len, &stream) != QSR_OK) {
    return 0;
  }
  qsr_sni_t sni;
  (void)qsr_tls_client_hello_sni(stream.data, stream.len, &sni);
  return 0;
}
