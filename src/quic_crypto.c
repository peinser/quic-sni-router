#include "qsr/quic_crypto.h"

#include <limits.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>

/* RFC 9001 §5.2 (v1) and RFC 9369 §5.1 (v2): public, version-specific salts
 * used to derive Initial-packet protection keys from the client's DCID. */
static const uint8_t quic_v1_initial_salt[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                                 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
static const uint8_t quic_v2_initial_salt[20] = {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
                                                 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9};

typedef struct qsr_quic_keying {
  const uint8_t *salt;
  size_t salt_len;
  const char *key_label;
  const char *iv_label;
  const char *hp_label;
} qsr_quic_keying_t;

[[nodiscard]] static qsr_status_t keying_for_version(uint32_t version, qsr_quic_keying_t *out) {
  switch (version) {
    case QSR_QUIC_V1:
      *out = (qsr_quic_keying_t){
          .salt = quic_v1_initial_salt,
          .salt_len = sizeof(quic_v1_initial_salt),
          .key_label = "quic key",
          .iv_label = "quic iv",
          .hp_label = "quic hp",
      };
      return QSR_OK;
    case QSR_QUIC_V2:
      *out = (qsr_quic_keying_t){
          .salt = quic_v2_initial_salt,
          .salt_len = sizeof(quic_v2_initial_salt),
          .key_label = "quicv2 key",
          .iv_label = "quicv2 iv",
          .hp_label = "quicv2 hp",
      };
      return QSR_OK;
    default:
      return QSR_ERR_UNSUPPORTED;
  }
}

static qsr_status_t hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *key, size_t key_len, uint8_t *out,
                                 size_t out_len) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (ctx == nullptr) {
    return QSR_ERR_INVALID;
  }
  qsr_status_t status = QSR_ERR_INVALID;
  size_t len = out_len;
  if (EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) == 1 &&
      EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 &&
      EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)salt_len) == 1 &&
      EVP_PKEY_CTX_set1_hkdf_key(ctx, key, (int)key_len) == 1 && EVP_PKEY_derive(ctx, out, &len) == 1 &&
      len == out_len) {
    status = QSR_OK;
  }
  EVP_PKEY_CTX_free(ctx);
  return status;
}

static qsr_status_t hkdf_expand(const uint8_t *secret, size_t secret_len, const uint8_t *info, size_t info_len,
                                uint8_t *out, size_t out_len) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (ctx == nullptr) {
    return QSR_ERR_INVALID;
  }
  qsr_status_t status = QSR_ERR_INVALID;
  size_t len = out_len;
  if (EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) == 1 &&
      EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 && EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, (int)secret_len) == 1 &&
      EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)info_len) == 1 && EVP_PKEY_derive(ctx, out, &len) == 1 &&
      len == out_len) {
    status = QSR_OK;
  }
  EVP_PKEY_CTX_free(ctx);
  return status;
}

static qsr_status_t hkdf_expand_label(const uint8_t *secret, size_t secret_len, const char *label, uint8_t *out,
                                      size_t out_len) {
  uint8_t info[64] = {0};
  const char prefix[] = "tls13 ";
  const size_t prefix_len = sizeof(prefix) - 1U;
  const size_t label_len = strlen(label);
  if (prefix_len + label_len > 255U || 4U + prefix_len + label_len > sizeof(info) || out_len > UINT16_MAX) {
    return QSR_ERR_INVALID;
  }
  info[0] = (uint8_t)(out_len >> 8U);
  info[1] = (uint8_t)out_len;
  info[2] = (uint8_t)(prefix_len + label_len);
  memcpy(info + 3U, prefix, prefix_len);
  memcpy(info + 3U + prefix_len, label, label_len);
  info[3U + prefix_len + label_len] = 0U;
  return hkdf_expand(secret, secret_len, info, 4U + prefix_len + label_len, out, out_len);
}

static qsr_status_t aes_ecb_mask(const uint8_t key[16], const uint8_t sample[16], uint8_t mask[16]) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    return QSR_ERR_INVALID;
  }
  int out_len = 0;
  qsr_status_t status = QSR_ERR_INVALID;
  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) == 1 && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
      EVP_EncryptUpdate(ctx, mask, &out_len, sample, 16) == 1 && out_len == 16) {
    status = QSR_OK;
  }
  EVP_CIPHER_CTX_free(ctx);
  return status;
}

static qsr_status_t aes_gcm_open(const uint8_t key[16], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                                 const uint8_t *ciphertext, size_t ciphertext_len, uint8_t *out, size_t *out_len) {
  if (ciphertext_len < 16U || aad_len > INT_MAX || ciphertext_len - 16U > INT_MAX) {
    return QSR_ERR_INVALID;
  }
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    return QSR_ERR_INVALID;
  }
  const size_t encrypted_len = ciphertext_len - 16U;
  const uint8_t *tag = ciphertext + encrypted_len;
  int len = 0;
  qsr_status_t status = QSR_ERR_INVALID;
  if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
      EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1 &&
      EVP_DecryptUpdate(ctx, nullptr, &len, aad, (int)aad_len) == 1 &&
      EVP_DecryptUpdate(ctx, out, &len, ciphertext, (int)encrypted_len) == 1) {
    int total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) == 1 &&
        EVP_DecryptFinal_ex(ctx, out + total, &len) == 1) {
      total += len;
      *out_len = (size_t)total;
      status = QSR_OK;
    }
  }
  EVP_CIPHER_CTX_free(ctx);
  return status;
}

qsr_status_t qsr_quic_initial_client_keys(uint32_t version, const uint8_t *dcid, size_t dcid_len,
                                          qsr_initial_keys_t *out) {
  if (dcid == nullptr || out == nullptr || dcid_len == 0U || dcid_len > QSR_MAX_QUIC_CID_LEN) {
    return QSR_ERR_INVALID;
  }
  qsr_quic_keying_t keying;
  if (keying_for_version(version, &keying) != QSR_OK) {
    return QSR_ERR_UNSUPPORTED;
  }
  uint8_t initial_secret[32] = {0};
  uint8_t client_secret[32] = {0};
  if (hkdf_extract(keying.salt, keying.salt_len, dcid, dcid_len, initial_secret, sizeof(initial_secret)) != QSR_OK ||
      hkdf_expand_label(initial_secret, sizeof(initial_secret), "client in", client_secret, sizeof(client_secret)) !=
          QSR_OK ||
      hkdf_expand_label(client_secret, sizeof(client_secret), keying.key_label, out->key, sizeof(out->key)) !=
          QSR_OK ||
      hkdf_expand_label(client_secret, sizeof(client_secret), keying.iv_label, out->iv, sizeof(out->iv)) != QSR_OK ||
      hkdf_expand_label(client_secret, sizeof(client_secret), keying.hp_label, out->hp, sizeof(out->hp)) != QSR_OK) {
    return QSR_ERR_INVALID;
  }
  return QSR_OK;
}

qsr_status_t qsr_quic_decrypt_initial(const uint8_t *packet, size_t packet_len, const qsr_quic_initial_t *initial,
                                      qsr_quic_plaintext_t *out) {
  if (packet == nullptr || initial == nullptr || out == nullptr || initial->dcid_len == 0U ||
      initial->packet_number_offset + 4U + 16U > packet_len ||
      initial->payload_len < QSR_MIN_INITIAL_PAYLOAD_LEN) {
    return QSR_ERR_INVALID;
  }

  qsr_initial_keys_t keys;
  qsr_status_t status = qsr_quic_initial_client_keys(initial->version, initial->dcid, initial->dcid_len, &keys);
  if (status != QSR_OK) {
    return status;
  }

  /* No zero-init: we memcpy the entire packet over `header` immediately
   * below, and only access bytes < packet_len afterwards. Zero-init would
   * touch 1500 bytes of stack on every Initial-decrypt for no benefit. */
  uint8_t header[QSR_MAX_DATAGRAM_SIZE];
  if (packet_len > sizeof(header)) {
    return QSR_ERR_INVALID;
  }
  memcpy(header, packet, packet_len);

  uint8_t mask[16] = {0};
  if (aes_ecb_mask(keys.hp, packet + initial->packet_number_offset + 4U, mask) != QSR_OK) {
    return QSR_ERR_INVALID;
  }

  header[0] ^= mask[0] & 0x0fU;
  const size_t pn_len = (size_t)(header[0] & 0x03U) + 1U;
  if (pn_len > initial->payload_len || initial->packet_number_offset + pn_len > packet_len) {
    return QSR_ERR_INVALID;
  }
  uint64_t packet_number = 0U;
  for (size_t i = 0U; i < pn_len; i++) {
    header[initial->packet_number_offset + i] ^= mask[i + 1U];
    packet_number = (packet_number << 8U) | header[initial->packet_number_offset + i];
  }

  uint8_t nonce[12] = {0};
  memcpy(nonce, keys.iv, sizeof(nonce));
  for (size_t i = 0U; i < 8U; i++) {
    nonce[sizeof(nonce) - 1U - i] ^= (uint8_t)(packet_number >> (i * 8U));
  }

  const size_t aad_len = initial->packet_number_offset + pn_len;
  const size_t ciphertext_len = initial->payload_len - pn_len;
  if (ciphertext_len > sizeof(out->data) || initial->packet_number_offset + pn_len + ciphertext_len > packet_len) {
    return QSR_ERR_INVALID;
  }
  out->len = 0U;
  return aes_gcm_open(keys.key, nonce, header, aad_len, packet + aad_len, ciphertext_len, out->data, &out->len);
}
