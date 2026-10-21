#include "qsr/quic_lb.h"

#include <openssl/evp.h>
#include <pthread.h>
#include <string.h>

static pthread_once_t aes_once = PTHREAD_ONCE_INIT;
static pthread_key_t aes_key;
static int aes_key_error;

static void free_aes(void *ctx) { EVP_CIPHER_CTX_free(ctx); }
static void create_aes_key(void) { aes_key_error = pthread_key_create(&aes_key, free_aes); }

/* Same thread-owned context pattern as cid_codec.c; reload copies only key
 * bytes, never mutable OpenSSL objects shared with the dataplane. */
static EVP_CIPHER_CTX *aes_context(const uint8_t key[16], bool encrypt) {
  if (pthread_once(&aes_once, create_aes_key) != 0 || aes_key_error != 0) {
    return nullptr;
  }
  EVP_CIPHER_CTX *ctx = pthread_getspecific(aes_key);
  if (ctx == nullptr) {
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr || pthread_setspecific(aes_key, ctx) != 0) {
      EVP_CIPHER_CTX_free(ctx);
      return nullptr;
    }
  }
  if (EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr, encrypt ? 1 : 0) != 1 ||
      EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
    return nullptr;
  }
  return ctx;
}

qsr_status_t qsr_quic_lb_config_init(qsr_quic_lb_t *lb, uint8_t id, uint8_t server_id_len,
                                     uint8_t nonce_len, const uint8_t *key) {
  if (lb == nullptr || id >= QSR_QUIC_LB_CONFIGS || server_id_len == 0 ||
      server_id_len > QSR_QUIC_LB_MAX_SERVER_ID || nonce_len < 4 || server_id_len + nonce_len > 19 ||
      lb->configs[id].active) {
    return QSR_ERR_INVALID;
  }
  qsr_quic_lb_config_t *config = &lb->configs[id];
  *config = (qsr_quic_lb_config_t){.active = true, .encrypted = key != nullptr,
                                  .server_id_len = server_id_len, .nonce_len = nonce_len};
  if (key != nullptr) {
    memcpy(config->key, key, sizeof(config->key));
  }
  lb->enabled = true;
  return QSR_OK;
}

qsr_status_t qsr_quic_lb_decode(const qsr_quic_lb_t *lb, const uint8_t *cid, size_t cid_len,
                                uint8_t *config_id, qsr_quic_lb_server_id_t *server_id) {
  if (lb == nullptr || cid == nullptr || config_id == nullptr || server_id == nullptr ||
      cid_len == 0 || cid_len > QSR_MAX_QUIC_CID_LEN) {
    return QSR_ERR_INVALID;
  }
  const uint8_t id = cid[0] >> 5U;
  if (!lb->enabled || id >= QSR_QUIC_LB_CONFIGS || !lb->configs[id].active) {
    return QSR_ERR_NOT_FOUND;
  }
  const qsr_quic_lb_config_t *config = &lb->configs[id];
  const size_t len = (size_t)config->server_id_len + config->nonce_len;
  if (cid_len < 1U + len) {
    return QSR_ERR_TRUNCATED;
  }
  uint8_t plaintext[19] = {0};
  if (!config->encrypted) {
    memcpy(plaintext, cid + 1, config->server_id_len);
  } else {
    EVP_CIPHER_CTX *ctx = aes_context(config->key, len != 16U);
    if (ctx == nullptr) {
      return QSR_ERR_INVALID;
    }
    int written = 0;
    if (len == 16U) {
      if (EVP_CipherUpdate(ctx, plaintext, &written, cid + 1, 16) != 1 || written != 16) {
        return QSR_ERR_INVALID;
      }
    } else {
      const size_t half = (len + 1U) / 2U;
      const bool odd = (len % 2U) != 0;
      uint8_t left[10] = {0};
      uint8_t right[10] = {0};
      memcpy(left, cid + 1, half);
      memcpy(right, cid + 1 + len / 2U, half);
      if (odd) {
        left[half - 1U] &= 0xf0;
        right[0] &= 0x0f;
      }
      /* Three rounds suffice when the whole server ID fits in the left half.
       * For longer IDs recover both halves, including the shared middle byte. */
      const unsigned last = config->server_id_len <= len / 2U ? 2U : 1U;
      for (unsigned pass = 4; pass >= last; pass--) {
        uint8_t input[16] = {0};
        uint8_t mask[16];
        const uint8_t *from = pass % 2U == 0 ? right : left;
        uint8_t *to = pass % 2U == 0 ? left : right;
        memcpy(input, from, half);
        input[14] = (uint8_t)len;
        input[15] = (uint8_t)pass;
        if (EVP_CipherUpdate(ctx, mask, &written, input, 16) != 1 || written != 16) {
          return QSR_ERR_INVALID;
        }
        for (size_t i = 0; i < half; i++) {
          to[i] ^= mask[i];
        }
        if (odd) {
          left[half - 1U] &= 0xf0;
          right[0] &= 0x0f;
        }
      }
      memcpy(plaintext, left, half);
      if (last == 1U) {
        for (size_t i = 0; i < half; i++) {
          plaintext[len / 2U + i] |= right[i];
        }
      }
    }
  }
  *server_id = (qsr_quic_lb_server_id_t){.len = config->server_id_len};
  memcpy(server_id->bytes, plaintext, server_id->len);
  *config_id = id;
  return QSR_OK;
}
