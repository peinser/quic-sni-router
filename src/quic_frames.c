#include "qsr/quic_frames.h"

#include "qsr/quic_initial.h"

#include <string.h>

void qsr_crypto_stream_init(qsr_crypto_stream_t *stream) {
  if (stream != nullptr) {
    memset(stream, 0, sizeof(*stream));
  }
}

void qsr_crypto_stream_merge(qsr_crypto_stream_t *dest, const qsr_crypto_stream_t *src) {
  if (dest == nullptr || src == nullptr) {
    return;
  }
  for (size_t i = 0U; i < src->len && i < QSR_MAX_CLIENT_HELLO_SIZE; i++) {
    if (src->received[i] != 0U) {
      dest->data[i] = src->data[i];
      dest->received[i] = 1U;
    }
  }
  if (src->len > dest->len) {
    dest->len = src->len;
  }
}

size_t qsr_crypto_stream_contiguous_len(const qsr_crypto_stream_t *stream) {
  if (stream == nullptr) {
    return 0U;
  }
  size_t len = 0U;
  while (len < stream->len && len < QSR_MAX_CLIENT_HELLO_SIZE && stream->received[len] != 0U) {
    len++;
  }
  return len;
}

qsr_status_t qsr_quic_extract_crypto(const uint8_t *plaintext, size_t plaintext_len, qsr_crypto_stream_t *stream) {
  if (plaintext == nullptr || stream == nullptr || plaintext_len > QSR_MAX_CLIENT_HELLO_SIZE) {
    return QSR_ERR_INVALID;
  }
  size_t offset = 0U;
  bool found = false;
  while (offset < plaintext_len) {
    const uint8_t frame_type = plaintext[offset++];
    /*
     * Client Initial frames legally include CRYPTO (0x06), PADDING (0x00),
     * PING (0x01), and ACK (0x02, 0x03). Anything else is either invalid in
     * Initial space (CONNECTION_CLOSE 0x1c is allowed but unexpected in the
     * very first packet) or signals a different packet type misrouted here.
     */
    if (frame_type == 0x00U || frame_type == 0x01U) {
      continue;
    }
    if (frame_type == 0x02U || frame_type == 0x03U) {
      /*
       * Skip ACK frame: largest_ack (varint), ack_delay (varint),
       * ack_range_count (varint), first_ack_range (varint), then ranges,
       * optional ECN counts. We only need the offsets to advance past it,
       * not the values themselves.
       */
      uint64_t v = 0U;
      size_t c = 0U;
      qsr_status_t s = qsr_quic_parse_varint(plaintext + offset, plaintext_len - offset, &v, &c);
      if (s != QSR_OK) {
        return s;
      }
      offset += c;
      s = qsr_quic_parse_varint(plaintext + offset, plaintext_len - offset, &v, &c);
      if (s != QSR_OK) {
        return s;
      }
      offset += c;
      uint64_t range_count = 0U;
      s = qsr_quic_parse_varint(plaintext + offset, plaintext_len - offset, &range_count, &c);
      if (s != QSR_OK) {
        return s;
      }
      offset += c;
      s = qsr_quic_parse_varint(plaintext + offset, plaintext_len - offset, &v, &c);
      if (s != QSR_OK) {
        return s;
      }
      offset += c;
      /*
       * Each ACK range is at least 2 varint bytes (1 byte minimum each for
       * gap + length). A range_count that can't possibly fit in the
       * remaining plaintext is an attempt to make us spin in the loop
       * below — bound it tightly. Only a client with a valid AEAD-decrypted
       * Initial can trigger this, so it's a self-DoS at worst, but cheap
       * to short-circuit.
       */
      if (range_count > (plaintext_len - offset) / 2U) {
        return QSR_ERR_INVALID;
      }
      for (uint64_t i = 0U; i < range_count; i++) {
        s = qsr_quic_parse_varint(plaintext + offset, plaintext_len - offset, &v, &c);
        if (s != QSR_OK) {
          return s;
        }
        offset += c;
        s = qsr_quic_parse_varint(plaintext + offset, plaintext_len - offset, &v, &c);
        if (s != QSR_OK) {
          return s;
        }
        offset += c;
      }
      if (frame_type == 0x03U) {
        for (int i = 0; i < 3; i++) {
          s = qsr_quic_parse_varint(plaintext + offset, plaintext_len - offset, &v, &c);
          if (s != QSR_OK) {
            return s;
          }
          offset += c;
        }
      }
      continue;
    }
    if (frame_type != 0x06U) {
      return QSR_ERR_UNSUPPORTED;
    }
    uint64_t crypto_offset = 0U;
    uint64_t crypto_len = 0U;
    size_t consumed = 0U;
    qsr_status_t status = qsr_quic_parse_varint(plaintext + offset, plaintext_len - offset, &crypto_offset, &consumed);
    if (status != QSR_OK) {
      return status;
    }
    offset += consumed;
    status = qsr_quic_parse_varint(plaintext + offset, plaintext_len - offset, &crypto_len, &consumed);
    if (status != QSR_OK) {
      return status;
    }
    offset += consumed;
    if (crypto_offset > QSR_MAX_CLIENT_HELLO_SIZE || crypto_len > QSR_MAX_CLIENT_HELLO_SIZE ||
        (size_t)crypto_len > plaintext_len - offset ||
        (size_t)crypto_offset > QSR_MAX_CLIENT_HELLO_SIZE - (size_t)crypto_len) {
      return QSR_ERR_INVALID;
    }
    memcpy(stream->data + (size_t)crypto_offset, plaintext + offset, (size_t)crypto_len);
    memset(stream->received + (size_t)crypto_offset, 1, (size_t)crypto_len);
    const size_t end = (size_t)crypto_offset + (size_t)crypto_len;
    if (end > stream->len) {
      stream->len = end;
    }
    offset += (size_t)crypto_len;
    found = true;
  }
  return found ? QSR_OK : QSR_ERR_NOT_FOUND;
}
