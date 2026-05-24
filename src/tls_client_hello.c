#include "qsr/tls_client_hello.h"

#include <ctype.h>
#include <string.h>

static uint16_t read_u16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8U) | p[1]); }
static uint32_t read_u24(const uint8_t *p) { return ((uint32_t)p[0] << 16U) | ((uint32_t)p[1] << 8U) | p[2]; }

static bool valid_hostname(const uint8_t *name, size_t len) {
  if (len == 0U || len > QSR_MAX_HOSTNAME_LEN || name[0] == '.' || name[len - 1U] == '.') {
    return false;
  }
  size_t label_len = 0U;
  for (size_t i = 0U; i < len; i++) {
    const unsigned char c = name[i];
    if (c == '.') {
      if (label_len == 0U || label_len > 63U || name[i - 1U] == '-') {
        return false;
      }
      label_len = 0U;
      continue;
    }
    if (!(isalnum(c) || c == '-')) {
      return false;
    }
    if (label_len == 0U && c == '-') {
      return false;
    }
    label_len++;
  }
  return label_len > 0U && label_len <= 63U && name[len - 1U] != '-';
}

qsr_status_t qsr_tls_client_hello_sni(const uint8_t *data, size_t len, qsr_sni_t *out) {
  if (data == nullptr || out == nullptr) {
    return QSR_ERR_INVALID;
  }
  if (len > QSR_MAX_CLIENT_HELLO_SIZE) {
    return QSR_ERR_INVALID;
  }
  memset(out, 0, sizeof(*out));

  size_t offset = 0U;
  if (len >= 5U && data[0] == 0x16U) {
    const size_t record_len = read_u16(data + 3U);
    if (record_len > len - 5U) {
      return QSR_ERR_TRUNCATED;
    }
    offset = 5U;
    len = 5U + record_len;
  }

  if (offset > len || 42U > len - offset || data[offset] != 0x01U) {
    return QSR_ERR_INVALID;
  }
  const size_t hello_len = read_u24(data + offset + 1U);
  offset += 4U;
  if (hello_len > len - offset) {
    return QSR_ERR_TRUNCATED;
  }
  const size_t hello_end = offset + hello_len;

  offset += 2U + 32U;
  if (offset > hello_end || 1U > hello_end - offset) {
    return QSR_ERR_TRUNCATED;
  }
  const size_t session_id_len = data[offset++];
  if (session_id_len > hello_end - offset || 2U > hello_end - offset - session_id_len) {
    return QSR_ERR_TRUNCATED;
  }
  offset += session_id_len;

  const size_t cipher_suites_len = read_u16(data + offset);
  offset += 2U;
  if (cipher_suites_len > hello_end - offset || 1U > hello_end - offset - cipher_suites_len ||
      (cipher_suites_len % 2U) != 0U) {
    return QSR_ERR_TRUNCATED;
  }
  offset += cipher_suites_len;

  const size_t compression_methods_len = data[offset++];
  if (compression_methods_len > hello_end - offset) {
    return QSR_ERR_TRUNCATED;
  }
  offset += compression_methods_len;

  if (offset == hello_end) {
    return QSR_ERR_NOT_FOUND;
  }
  if (offset > hello_end || 2U > hello_end - offset) {
    return QSR_ERR_TRUNCATED;
  }
  const size_t extensions_len = read_u16(data + offset);
  offset += 2U;
  if (extensions_len > hello_end - offset) {
    return QSR_ERR_TRUNCATED;
  }
  const size_t extensions_end = offset + extensions_len;

  while (offset + 4U <= extensions_end) {
    const uint16_t type = read_u16(data + offset);
    const size_t ext_len = read_u16(data + offset + 2U);
    offset += 4U;
    if (ext_len > extensions_end - offset) {
      return QSR_ERR_TRUNCATED;
    }
    if (type == 0U) {
      if (ext_len < 2U) {
        return QSR_ERR_INVALID;
      }
      size_t sni_offset = offset + 2U;
      const size_t list_len = read_u16(data + offset);
      if (list_len > (offset + ext_len) - sni_offset) {
        return QSR_ERR_TRUNCATED;
      }
      const size_t list_end = sni_offset + list_len;
      while (sni_offset + 3U <= list_end) {
        const uint8_t name_type = data[sni_offset++];
        const size_t name_len = read_u16(data + sni_offset);
        sni_offset += 2U;
        if (name_len > list_end - sni_offset) {
          return QSR_ERR_TRUNCATED;
        }
        if (name_type == 0U) {
          if (!valid_hostname(data + sni_offset, name_len)) {
            return QSR_ERR_INVALID;
          }
          memcpy(out->name, data + sni_offset, name_len);
          out->name[name_len] = '\0';
          return QSR_OK;
        }
        sni_offset += name_len;
      }
      return QSR_ERR_NOT_FOUND;
    }
    offset += ext_len;
  }

  return QSR_ERR_NOT_FOUND;
}
