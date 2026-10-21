#include "qsr/cid_codec.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <pthread.h>
#include <string.h>

/* Each calling thread owns one reusable HMAC context. Thread exit releases
 * it; pthread TLS avoids shared mutable crypto state with reload workers or
 * library callers. */
static pthread_key_t mac_key;
static pthread_once_t mac_once = PTHREAD_ONCE_INIT;
static int mac_key_error;

static void free_mac(void *ctx) { EVP_MAC_CTX_free(ctx); }

static void create_mac_key(void) { mac_key_error = pthread_key_create(&mac_key, free_mac); }

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

qsr_status_t qsr_cid_codec_init_from_hex(qsr_cid_codec_t *codec, const char *hex_key) {
  if (codec == nullptr || hex_key == nullptr) {
    return QSR_ERR_INVALID;
  }
  memset(codec, 0, sizeof(*codec));
  if (strlen(hex_key) != (size_t)QSR_CID_KEY_LEN * 2U) {
    return QSR_ERR_INVALID;
  }
  for (size_t i = 0U; i < QSR_CID_KEY_LEN; i++) {
    const int hi = hex_nibble(hex_key[i * 2U]);
    const int lo = hex_nibble(hex_key[i * 2U + 1U]);
    if (hi < 0 || lo < 0) {
      memset(codec, 0, sizeof(*codec));
      return QSR_ERR_INVALID;
    }
    codec->key[i] = (uint8_t)(((unsigned)hi << 4U) | (unsigned)lo);
  }
  codec->enabled = true;
  return QSR_OK;
}

/* Authenticate the complete routing prefix. Unlike CTR plus fixed plaintext,
 * a MAC binds the server id to the nonce. Replay is intentionally allowed:
 * CID routing is not QUIC address validation. */
static bool cid_tag(const qsr_cid_codec_t *codec, const uint8_t *prefix, uint8_t tag[32]) {
  if (pthread_once(&mac_once, create_mac_key) != 0 || mac_key_error != 0) {
    return false;
  }
  EVP_MAC_CTX *ctx = pthread_getspecific(mac_key);
  if (ctx == nullptr) {
    EVP_MAC *mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (mac == nullptr) {
      return false;
    }
    ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (ctx == nullptr || pthread_setspecific(mac_key, ctx) != 0) {
      EVP_MAC_CTX_free(ctx);
      return false;
    }
  }
  char digest[] = "SHA256";
  OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0), OSSL_PARAM_END};
  size_t len = 0;
  return EVP_MAC_init(ctx, codec->key, QSR_CID_KEY_LEN, params) == 1 && EVP_MAC_update(ctx, prefix, 9U) == 1 &&
         EVP_MAC_final(ctx, tag, &len, 32U) == 1 && len == 32U;
}

qsr_status_t qsr_cid_codec_encode(const qsr_cid_codec_t *codec, uint8_t server_id,
                                  const uint8_t nonce[QSR_CID_NONCE_LEN], uint8_t out[QSR_CID_ENCODED_LEN]) {
  if (codec == nullptr || !codec->enabled || out == nullptr || nonce == nullptr || server_id == 0U) {
    return QSR_ERR_INVALID;
  }
  out[0] = QSR_CID_ENCODED_VERSION;
  memcpy(&out[1], nonce, QSR_CID_NONCE_LEN);
  out[8] = server_id;
  uint8_t tag[32];
  if (!cid_tag(codec, out, tag)) {
    return QSR_ERR_INVALID;
  }
  memcpy(out + 9U, tag, QSR_CID_TAG_LEN);
  return QSR_OK;
}

qsr_status_t qsr_cid_codec_decode(const qsr_cid_codec_t *codec, const uint8_t *cid, size_t cid_len,
                                  uint8_t *server_id) {
  if (codec == nullptr || !codec->enabled || cid == nullptr || server_id == nullptr) {
    return QSR_ERR_INVALID;
  }
  if (cid_len != QSR_CID_ENCODED_LEN || cid[0] != QSR_CID_ENCODED_VERSION) {
    return QSR_ERR_INVALID;
  }
  uint8_t tag[32];
  if (cid[8] == 0U || !cid_tag(codec, cid, tag) || CRYPTO_memcmp(cid + 9U, tag, QSR_CID_TAG_LEN) != 0) {
    return QSR_ERR_INVALID;
  }
  *server_id = cid[8];
  return QSR_OK;
}
