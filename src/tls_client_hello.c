#include "qsr/tls_client_hello.h"

#include <ctype.h>
#include <string.h>

/*
 * Parses the SNI out of a TLS 1.2/1.3 ClientHello. Input is either:
 *   - a raw TLS handshake message (what we get after CRYPTO-frame reassembly
 *     of a QUIC Initial), starting with a 1-byte handshake type (0x01), or
 *   - a TLS record framing one (legacy/test convenience), starting with a
 *     5-byte record header where byte[0] == 0x16.
 *
 * Implementation shape: a small forward-only reader over the input bytes.
 * Each typed read does its own bounds check and returns QSR_ERR_TRUNCATED
 * on short input; nested length-prefixed fields narrow the reader's `end`
 * for the duration of that field's body, so an inner reader literally
 * cannot walk past its containing structure's declared length.
 *
 * Replaces the earlier flat parser which had 14 separate
 * `if (offset > end || N > end - offset)` checks. Same semantics, much
 * easier to audit.
 */

typedef struct reader {
  const uint8_t *data;
  size_t end;     /* exclusive */
  size_t offset;
} reader_t;

static reader_t r_init(const uint8_t *data, size_t len) {
  return (reader_t){.data = data, .end = len, .offset = 0U};
}

[[nodiscard]] static bool r_has(const reader_t *r, size_t n) { return r->offset + n <= r->end; }

[[nodiscard]] static size_t r_remaining(const reader_t *r) { return r->end - r->offset; }

[[nodiscard]] static qsr_status_t r_u8(reader_t *r, uint8_t *out) {
  if (!r_has(r, 1U)) {
    return QSR_ERR_TRUNCATED;
  }
  *out = r->data[r->offset++];
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t r_u16(reader_t *r, uint16_t *out) {
  if (!r_has(r, 2U)) {
    return QSR_ERR_TRUNCATED;
  }
  *out = (uint16_t)((uint16_t)r->data[r->offset] << 8U | r->data[r->offset + 1U]);
  r->offset += 2U;
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t r_u24(reader_t *r, uint32_t *out) {
  if (!r_has(r, 3U)) {
    return QSR_ERR_TRUNCATED;
  }
  *out = ((uint32_t)r->data[r->offset] << 16U) | ((uint32_t)r->data[r->offset + 1U] << 8U) |
         (uint32_t)r->data[r->offset + 2U];
  r->offset += 3U;
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t r_skip(reader_t *r, size_t n) {
  if (!r_has(r, n)) {
    return QSR_ERR_TRUNCATED;
  }
  r->offset += n;
  return QSR_OK;
}

/*
 * Borrow the next `n` bytes as a child reader. The parent's offset
 * advances past the borrowed region; the child reader is independent and
 * cannot read outside it.
 */
[[nodiscard]] static qsr_status_t r_subreader(reader_t *r, size_t n, reader_t *child) {
  if (!r_has(r, n)) {
    return QSR_ERR_TRUNCATED;
  }
  *child = (reader_t){.data = r->data + r->offset, .end = n, .offset = 0U};
  r->offset += n;
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t r_subreader_available(reader_t *r, size_t declared_len, reader_t *child,
                                                        bool *truncated) {
  const size_t available = r_remaining(r);
  const size_t child_len = declared_len < available ? declared_len : available;
  *child = (reader_t){.data = r->data + r->offset, .end = child_len, .offset = 0U};
  r->offset += child_len;
  *truncated = child_len < declared_len;
  return child_len == 0U && declared_len > 0U ? QSR_ERR_TRUNCATED : QSR_OK;
}

[[nodiscard]] static const uint8_t *r_ptr(const reader_t *r) { return r->data + r->offset; }

/*
 * Subset of RFC 1035 §2.3.1 hostname validation: lowercase ASCII LDH plus
 * '.', label length ≤ 63, no leading or trailing '-' per label, no empty
 * labels. SNI route lookups normalize to lowercase before this is called,
 * so uppercase is allowed by isalnum and folded by the caller.
 */
[[nodiscard]] static bool valid_hostname(const uint8_t *name, size_t len) {
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

/*
 * Parse the SNI extension body (everything inside the extension data, after
 * the 4-byte type+length header). RFC 6066 §3: server_name_list (uint16
 * length) of ServerName entries (NameType u8 + HostName u16-length-prefixed
 * opaque bytes). We only care about NameType=0 (host_name).
 */
[[nodiscard]] static qsr_status_t parse_sni_extension(reader_t r, qsr_sni_t *out) {
  uint16_t list_len = 0U;
  qsr_status_t status = r_u16(&r, &list_len);
  if (status != QSR_OK) {
    return status;
  }
  reader_t list;
  status = r_subreader(&r, list_len, &list);
  if (status != QSR_OK) {
    return status;
  }
  while (r_remaining(&list) >= 3U) {
    uint8_t name_type = 0U;
    uint16_t name_len = 0U;
    if (r_u8(&list, &name_type) != QSR_OK || r_u16(&list, &name_len) != QSR_OK) {
      return QSR_ERR_TRUNCATED;
    }
    if (!r_has(&list, name_len)) {
      return QSR_ERR_TRUNCATED;
    }
    if (name_type == 0U) {
      const uint8_t *name = r_ptr(&list);
      if (!valid_hostname(name, name_len)) {
        return QSR_ERR_INVALID;
      }
      memcpy(out->name, name, name_len);
      out->name[name_len] = '\0';
      return QSR_OK;
    }
    (void)r_skip(&list, name_len);
  }
  return QSR_ERR_NOT_FOUND;
}

qsr_status_t qsr_tls_client_hello_sni(const uint8_t *data, size_t len, qsr_sni_t *out) {
  if (data == nullptr || out == nullptr || len > QSR_MAX_CLIENT_HELLO_SIZE) {
    return QSR_ERR_INVALID;
  }
  memset(out, 0, sizeof(*out));

  reader_t r = r_init(data, len);

  /*
   * Optional TLS record wrapper. The QUIC Initial path always passes a raw
   * handshake message (CRYPTO-frame reassembled), but tests and other
   * callers may pass the full TLS record. Detect via the handshake content
   * type 0x16 in byte 0 and a plausible record length, then narrow the
   * reader to the record body.
   */
  if (r_has(&r, 5U) && data[0] == 0x16U) {
    (void)r_skip(&r, 3U); /* content type + legacy version */
    uint16_t record_len = 0U;
    (void)r_u16(&r, &record_len);
    reader_t record;
    if (r_subreader(&r, record_len, &record) != QSR_OK) {
      return QSR_ERR_TRUNCATED;
    }
    r = record;
  }

  /*
   * Handshake message: HandshakeType (uint8, must be 0x01 client_hello)
   * + uint24 length + body.
   */
  uint8_t msg_type = 0U;
  if (r_u8(&r, &msg_type) != QSR_OK || msg_type != 0x01U) {
    return QSR_ERR_INVALID;
  }
  uint32_t hello_len = 0U;
  if (r_u24(&r, &hello_len) != QSR_OK) {
    return QSR_ERR_TRUNCATED;
  }
  reader_t hello;
  bool hello_truncated = false;
  if (r_subreader_available(&r, hello_len, &hello, &hello_truncated) != QSR_OK) {
    return QSR_ERR_TRUNCATED;
  }

  /*
   * ClientHello body: legacy_version (2) + random (32) + session_id
   * (uint8-length-prefixed) + cipher_suites (uint16-length-prefixed,
   * length must be multiple of 2) + compression_methods (uint8-length-
   * prefixed) + extensions (uint16-length-prefixed).
   */
  if (r_skip(&hello, 2U + 32U) != QSR_OK) {
    return QSR_ERR_TRUNCATED;
  }
  uint8_t session_id_len = 0U;
  if (r_u8(&hello, &session_id_len) != QSR_OK || r_skip(&hello, session_id_len) != QSR_OK) {
    return QSR_ERR_TRUNCATED;
  }
  uint16_t cipher_suites_len = 0U;
  if (r_u16(&hello, &cipher_suites_len) != QSR_OK) {
    return QSR_ERR_TRUNCATED;
  }
  if ((cipher_suites_len % 2U) != 0U) {
    return QSR_ERR_INVALID;
  }
  if (r_skip(&hello, cipher_suites_len) != QSR_OK) {
    return QSR_ERR_TRUNCATED;
  }
  uint8_t compression_methods_len = 0U;
  if (r_u8(&hello, &compression_methods_len) != QSR_OK ||
      r_skip(&hello, compression_methods_len) != QSR_OK) {
    return QSR_ERR_TRUNCATED;
  }

  /* No extensions block at all is legal (TLS 1.2 minimal); no SNI is then
   * possible. TLS 1.3 always has extensions but we don't enforce that. */
  if (r_remaining(&hello) == 0U) {
    return QSR_ERR_NOT_FOUND;
  }
  uint16_t extensions_len = 0U;
  if (r_u16(&hello, &extensions_len) != QSR_OK) {
    return QSR_ERR_TRUNCATED;
  }
  reader_t extensions;
  bool extensions_truncated = false;
  if (r_subreader_available(&hello, extensions_len, &extensions, &extensions_truncated) != QSR_OK) {
    return QSR_ERR_TRUNCATED;
  }

  /* Walk extensions looking for type 0 (server_name). */
  while (r_remaining(&extensions) >= 4U) {
    uint16_t ext_type = 0U;
    uint16_t ext_len = 0U;
    (void)r_u16(&extensions, &ext_type);
    (void)r_u16(&extensions, &ext_len);
    reader_t ext_body;
    if (r_subreader(&extensions, ext_len, &ext_body) != QSR_OK) {
      return QSR_ERR_TRUNCATED;
    }
    if (ext_type == 0U) {
      return parse_sni_extension(ext_body, out);
    }
  }
  return hello_truncated || extensions_truncated ? QSR_ERR_TRUNCATED : QSR_ERR_NOT_FOUND;
}
