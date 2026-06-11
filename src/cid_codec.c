#include "qsr/cid_codec.h"

#include <openssl/evp.h>
#include <string.h>

/*
 * 7-byte ASCII tag baked into the plaintext payload. Decode rejects any CID
 * whose decrypted bytes [1..7] do not match. With a keyed cipher, an attacker
 * cannot construct a CID that produces this magic on decrypt without the
 * shared key, so routing on a magic-passing decode is safe.
 */
static const uint8_t QSR_CID_MAGIC[7] = {'q', 's', 'r', 'l', 'r', 't', 'r'};

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

/*
 * AES-128-CTR over an 8-byte payload, IV = version || nonce || zeros[8]. CTR
 * is symmetric so the same routine encrypts and decrypts.
 */
[[nodiscard]] static qsr_status_t aes128_ctr_crypt(const uint8_t key[QSR_CID_KEY_LEN], const uint8_t iv[QSR_CID_KEY_LEN],
                                                   const uint8_t in[QSR_CID_PAYLOAD_LEN],
                                                   uint8_t out[QSR_CID_PAYLOAD_LEN]) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    return QSR_ERR_INVALID;
  }
  qsr_status_t status = QSR_ERR_INVALID;
  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key, iv) == 1) {
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, out, &outlen, in, (int)QSR_CID_PAYLOAD_LEN) == 1 &&
        (size_t)outlen == QSR_CID_PAYLOAD_LEN) {
      status = QSR_OK;
    }
  }
  EVP_CIPHER_CTX_free(ctx);
  return status;
}

static void build_iv(uint8_t iv[QSR_CID_KEY_LEN], const uint8_t nonce[QSR_CID_NONCE_LEN]) {
  iv[0] = QSR_CID_ENCODED_VERSION;
  memcpy(&iv[1], nonce, QSR_CID_NONCE_LEN);
  memset(&iv[1U + QSR_CID_NONCE_LEN], 0, QSR_CID_KEY_LEN - 1U - QSR_CID_NONCE_LEN);
}

qsr_status_t qsr_cid_codec_encode(const qsr_cid_codec_t *codec, uint8_t server_id,
                                  const uint8_t nonce[QSR_CID_NONCE_LEN], uint8_t out[QSR_CID_ENCODED_LEN]) {
  if (codec == nullptr || !codec->enabled || out == nullptr || nonce == nullptr || server_id == 0U) {
    return QSR_ERR_INVALID;
  }
  uint8_t plaintext[QSR_CID_PAYLOAD_LEN];
  plaintext[0] = server_id;
  memcpy(&plaintext[1], QSR_CID_MAGIC, sizeof(QSR_CID_MAGIC));

  uint8_t iv[QSR_CID_KEY_LEN];
  build_iv(iv, nonce);

  out[0] = QSR_CID_ENCODED_VERSION;
  memcpy(&out[1], nonce, QSR_CID_NONCE_LEN);
  return aes128_ctr_crypt(codec->key, iv, plaintext, &out[1U + QSR_CID_NONCE_LEN]);
}

qsr_status_t qsr_cid_codec_decode(const qsr_cid_codec_t *codec, const uint8_t *cid, size_t cid_len,
                                  uint8_t *server_id) {
  if (codec == nullptr || !codec->enabled || cid == nullptr || server_id == nullptr) {
    return QSR_ERR_INVALID;
  }
  if (cid_len != QSR_CID_ENCODED_LEN || cid[0] != QSR_CID_ENCODED_VERSION) {
    return QSR_ERR_INVALID;
  }
  uint8_t iv[QSR_CID_KEY_LEN];
  build_iv(iv, &cid[1]);

  uint8_t plaintext[QSR_CID_PAYLOAD_LEN];
  if (aes128_ctr_crypt(codec->key, iv, &cid[1U + QSR_CID_NONCE_LEN], plaintext) != QSR_OK) {
    return QSR_ERR_INVALID;
  }
  if (plaintext[0] == 0U || memcmp(&plaintext[1], QSR_CID_MAGIC, sizeof(QSR_CID_MAGIC)) != 0) {
    return QSR_ERR_INVALID;
  }
  *server_id = plaintext[0];
  return QSR_OK;
}
