#include "qsr/config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <yaml.h>
#include <openssl/crypto.h>

/*
 * libyaml document-API config loader.
 *
 * Grammar accepted (block or flow style):
 *
 *   listen:
 *     udp: ":443"
 *   sessions:
 *     idleTimeout: 60s   # optional "s" suffix
 *     maxSessions: 100000
 *   routes:
 *     <sni>:
 *       host: <hostname-or-ip>
 *       port: <1..65535>
 *
 * Unknown top-level keys or per-route keys are rejected: a typo should be an
 * error, not a silent default. Anchors (&name) and aliases (*name) work
 * because the document API resolves them for us; comments and quoted scalars
 * with literal '#' work because libyaml is YAML 1.1 compliant.
 */

void qsr_config_default(qsr_config_t *config) {
  if (config == nullptr) {
    return;
  }
  memset(config, 0, sizeof(*config));
  static const char default_listen[] = ":443";
  memcpy(config->listen_udp, default_listen, sizeof(default_listen));
  config->idle_timeout_seconds = 60U;
  config->max_sessions = QSR_MAX_SESSIONS_DEFAULT;
  qsr_route_table_init(&config->routes);
}

[[nodiscard]] static qsr_status_t parse_u32(const char *text, uint32_t min, uint32_t max, uint32_t *out) {
  if (text == nullptr || out == nullptr || *text == '\0') {
    return QSR_ERR_INVALID;
  }
  errno = 0;
  char *end = nullptr;
  const unsigned long value = strtoul(text, &end, 10);
  if (errno != 0 || end == text || value < min || value > max) {
    return QSR_ERR_INVALID;
  }
  /* Allow an optional "s" suffix for durations like "60s"; nothing else. */
  if (*end != '\0' && strcmp(end, "s") != 0) {
    return QSR_ERR_INVALID;
  }
  *out = (uint32_t)value;
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t parse_size(const char *text, size_t min, size_t max, size_t *out) {
  if (text == nullptr || out == nullptr || *text == '\0') {
    return QSR_ERR_INVALID;
  }
  errno = 0;
  char *end = nullptr;
  const unsigned long long value = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value < min || value > max) {
    return QSR_ERR_INVALID;
  }
  *out = (size_t)value;
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t parse_bool(const char *text, bool *out) {
  if (text == nullptr || out == nullptr) {
    return QSR_ERR_INVALID;
  }
  if (strcmp(text, "true") == 0) {
    *out = true;
    return QSR_OK;
  }
  if (strcmp(text, "false") == 0) {
    *out = false;
    return QSR_OK;
  }
  return QSR_ERR_INVALID;
}

[[nodiscard]] static qsr_status_t parse_port(const char *text, uint16_t *out) {
  uint32_t value = 0U;
  qsr_status_t status = parse_u32(text, 1U, 65535U, &value);
  if (status != QSR_OK) {
    return status;
  }
  *out = (uint16_t)value;
  return QSR_OK;
}

/* Copy a YAML scalar node into a fixed-size NUL-terminated buffer. */
[[nodiscard]] static qsr_status_t copy_scalar(const yaml_node_t *node, char *out, size_t out_max) {
  if (node == nullptr || node->type != YAML_SCALAR_NODE) {
    return QSR_ERR_INVALID;
  }
  const size_t len = node->data.scalar.length;
  if (len + 1U > out_max) {
    return QSR_ERR_INVALID;
  }
  /*
   * Reject scalars containing an embedded NUL — every consumer here uses
   * strcmp/strncmp, which would treat the NUL as a string terminator and
   * silently accept the prefix. Operator config is trusted but the check
   * is one line and closes a category of footguns.
   */
  if (memchr(node->data.scalar.value, 0, len) != nullptr) {
    return QSR_ERR_INVALID;
  }
  memcpy(out, node->data.scalar.value, len);
  out[len] = '\0';
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t parse_listen(yaml_document_t *doc, yaml_node_t *node, qsr_config_t *config) {
  if (node == nullptr || node->type != YAML_MAPPING_NODE) {
    return QSR_ERR_INVALID;
  }
  for (yaml_node_pair_t *pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; pair++) {
    yaml_node_t *k = yaml_document_get_node(doc, pair->key);
    yaml_node_t *v = yaml_document_get_node(doc, pair->value);
    char key[16];
    qsr_status_t status = copy_scalar(k, key, sizeof(key));
    if (status != QSR_OK) {
      return status;
    }
    if (strcmp(key, "udp") != 0) {
      return QSR_ERR_INVALID;
    }
    status = copy_scalar(v, config->listen_udp, sizeof(config->listen_udp));
    if (status != QSR_OK) {
      return status;
    }
    if (config->listen_udp[0] == '\0') {
      return QSR_ERR_INVALID;
    }
  }
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t parse_sessions(yaml_document_t *doc, yaml_node_t *node, qsr_config_t *config) {
  if (node == nullptr || node->type != YAML_MAPPING_NODE) {
    return QSR_ERR_INVALID;
  }
  for (yaml_node_pair_t *pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; pair++) {
    yaml_node_t *k = yaml_document_get_node(doc, pair->key);
    yaml_node_t *v = yaml_document_get_node(doc, pair->value);
    char key[32];
    char value[32];
    qsr_status_t status = copy_scalar(k, key, sizeof(key));
    if (status != QSR_OK) {
      return status;
    }
    status = copy_scalar(v, value, sizeof(value));
    if (status != QSR_OK) {
      return status;
    }
    if (strcmp(key, "idleTimeout") == 0) {
      status = parse_u32(value, 1U, 86400U, &config->idle_timeout_seconds);
    } else if (strcmp(key, "maxSessions") == 0) {
      status = parse_size(value, 1U, (size_t)QSR_MAX_SESSIONS_DEFAULT * 10U, &config->max_sessions);
    } else {
      return QSR_ERR_INVALID;
    }
    if (status != QSR_OK) {
      return status;
    }
  }
  return QSR_OK;
}

static qsr_status_t parse_quic_lb_ids(yaml_document_t *doc, const yaml_node_t *node, qsr_route_table_t *routes,
                                     size_t route_index) {
  if (node->type != YAML_MAPPING_NODE || node->data.mapping.pairs.start == node->data.mapping.pairs.top) {
    return QSR_ERR_INVALID;
  }
  for (yaml_node_pair_t *pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; pair++) {
    char rotation[8];
    char hex[QSR_QUIC_LB_MAX_SERVER_ID * 2U + 1U];
    size_t config_id = 0;
    if (copy_scalar(yaml_document_get_node(doc, pair->key), rotation, sizeof(rotation)) != QSR_OK ||
        parse_size(rotation, 0, QSR_QUIC_LB_CONFIGS - 1U, &config_id) != QSR_OK ||
        copy_scalar(yaml_document_get_node(doc, pair->value), hex, sizeof(hex)) != QSR_OK) {
      return QSR_ERR_INVALID;
    }
    const size_t hex_len = strlen(hex);
    qsr_quic_lb_server_id_t id = {0};
    size_t len = 0;
    if (hex_len == 0 || hex_len % 2U != 0 ||
        OPENSSL_hexstr2buf_ex(id.bytes, sizeof(id.bytes), &len, hex, '\0') != 1 || len != hex_len / 2U) {
      return QSR_ERR_INVALID;
    }
    id.len = (uint8_t)len;
    if (qsr_route_table_set_quic_lb_id(routes, route_index, (uint8_t)config_id, &id) != QSR_OK) {
      return QSR_ERR_INVALID;
    }
  }
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t parse_route_body(yaml_document_t *doc, yaml_node_t *node, qsr_config_t *config,
                                                   const char *sni) {
  if (node == nullptr || node->type != YAML_MAPPING_NODE) {
    return QSR_ERR_INVALID;
  }
  char host[QSR_MAX_ADDR_LEN + 1U] = {0};
  uint16_t port = 0U;
  uint8_t server_id = 0U;
  yaml_node_t *lb_ids = nullptr;
  for (yaml_node_pair_t *pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; pair++) {
    yaml_node_t *k = yaml_document_get_node(doc, pair->key);
    yaml_node_t *v = yaml_document_get_node(doc, pair->value);
    char key[16];
    qsr_status_t status = copy_scalar(k, key, sizeof(key));
    if (status != QSR_OK) {
      return status;
    }
    if (strcmp(key, "host") == 0) {
      status = copy_scalar(v, host, sizeof(host));
      if (status != QSR_OK || host[0] == '\0') {
        return QSR_ERR_INVALID;
      }
    } else if (strcmp(key, "port") == 0) {
      char port_text[16];
      status = copy_scalar(v, port_text, sizeof(port_text));
      if (status != QSR_OK) {
        return status;
      }
      status = parse_port(port_text, &port);
      if (status != QSR_OK) {
        return status;
      }
    } else if (strcmp(key, "quicLbServerIds") == 0) {
      if (lb_ids != nullptr) {
        return QSR_ERR_INVALID;
      }
      lb_ids = v;
    } else if (strcmp(key, "serverId") == 0) {
      char sid_text[8];
      status = copy_scalar(v, sid_text, sizeof(sid_text));
      if (status != QSR_OK) {
        return status;
      }
      uint32_t sid = 0U;
      status = parse_u32(sid_text, 1U, 255U, &sid);
      if (status != QSR_OK) {
        return status;
      }
      server_id = (uint8_t)sid;
    } else {
      return QSR_ERR_INVALID;
    }
  }
  if (host[0] == '\0' || port == 0U) {
    return QSR_ERR_INVALID;
  }
  const qsr_status_t status = qsr_route_table_add(&config->routes, sni, host, port, server_id);
  if (status != QSR_OK || lb_ids == nullptr) {
    return status;
  }
  return parse_quic_lb_ids(doc, lb_ids, &config->routes, config->routes.count - 1U);
}

[[nodiscard]] static qsr_status_t parse_logging(yaml_document_t *doc, yaml_node_t *node, qsr_config_t *config) {
  if (node == nullptr || node->type != YAML_MAPPING_NODE) {
    return QSR_ERR_INVALID;
  }
  for (yaml_node_pair_t *pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; pair++) {
    yaml_node_t *k = yaml_document_get_node(doc, pair->key);
    yaml_node_t *v = yaml_document_get_node(doc, pair->value);
    char key[16];
    char value[16];
    qsr_status_t status = copy_scalar(k, key, sizeof(key));
    if (status != QSR_OK) {
      return status;
    }
    status = copy_scalar(v, value, sizeof(value));
    if (status != QSR_OK) {
      return status;
    }
    if (strcmp(key, "connections") == 0) {
      status = parse_bool(value, &config->log_connections);
    } else {
      return QSR_ERR_INVALID;
    }
    if (status != QSR_OK) {
      return status;
    }
  }
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t parse_cid_encoding(yaml_document_t *doc, yaml_node_t *node, qsr_config_t *config) {
  if (node == nullptr || node->type != YAML_MAPPING_NODE) {
    return QSR_ERR_INVALID;
  }
  char key_hex[QSR_CID_KEY_LEN * 2U + 1U] = {0};
  for (yaml_node_pair_t *pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; pair++) {
    yaml_node_t *k = yaml_document_get_node(doc, pair->key);
    yaml_node_t *v = yaml_document_get_node(doc, pair->value);
    char key[16];
    qsr_status_t status = copy_scalar(k, key, sizeof(key));
    if (status != QSR_OK) {
      return status;
    }
    if (strcmp(key, "key") == 0) {
      status = copy_scalar(v, key_hex, sizeof(key_hex));
      if (status != QSR_OK) {
        return status;
      }
    } else {
      return QSR_ERR_INVALID;
    }
  }
  if (key_hex[0] == '\0') {
    return QSR_ERR_INVALID;
  }
  return qsr_cid_codec_init_from_hex(&config->cid_codec, key_hex);
}

[[nodiscard]] static qsr_status_t parse_routes(yaml_document_t *doc, yaml_node_t *node, qsr_config_t *config) {
  if (node == nullptr || node->type != YAML_MAPPING_NODE) {
    return QSR_ERR_INVALID;
  }
  for (yaml_node_pair_t *pair = node->data.mapping.pairs.start; pair < node->data.mapping.pairs.top; pair++) {
    yaml_node_t *k = yaml_document_get_node(doc, pair->key);
    yaml_node_t *v = yaml_document_get_node(doc, pair->value);
    char sni[QSR_MAX_HOSTNAME_LEN + 1U] = {0};
    qsr_status_t status = copy_scalar(k, sni, sizeof(sni));
    if (status != QSR_OK || sni[0] == '\0') {
      return QSR_ERR_INVALID;
    }
    status = parse_route_body(doc, v, config, sni);
    if (status != QSR_OK) {
      return status;
    }
  }
  return QSR_OK;
}

static qsr_status_t parse_quic_lb(yaml_document_t *doc, yaml_node_t *node, qsr_quic_lb_t *lb) {
  if (node->type != YAML_MAPPING_NODE || lb->enabled ||
      node->data.mapping.pairs.top - node->data.mapping.pairs.start != 1) {
    return QSR_ERR_INVALID;
  }
  const yaml_node_pair_t *pair = node->data.mapping.pairs.start;
  char key[32];
  if (copy_scalar(yaml_document_get_node(doc, pair->key), key, sizeof(key)) != QSR_OK ||
      strcmp(key, "configurations") != 0) {
    return QSR_ERR_INVALID;
  }
  yaml_node_t *list = yaml_document_get_node(doc, pair->value);
  if (list->type != YAML_SEQUENCE_NODE || list->data.sequence.items.start == list->data.sequence.items.top) {
    return QSR_ERR_INVALID;
  }
  for (yaml_node_item_t *item = list->data.sequence.items.start; item < list->data.sequence.items.top; item++) {
    yaml_node_t *entry = yaml_document_get_node(doc, *item);
    if (entry->type != YAML_MAPPING_NODE) {
      return QSR_ERR_INVALID;
    }
    size_t rotation = 0;
    size_t sid_len = 0;
    size_t nonce_len = 0;
    unsigned seen = 0;
    qsr_cid_codec_t parsed_key = {0};
    for (yaml_node_pair_t *field = entry->data.mapping.pairs.start; field < entry->data.mapping.pairs.top; field++) {
      char name[32];
      char value[33];
      if (copy_scalar(yaml_document_get_node(doc, field->key), name, sizeof(name)) != QSR_OK ||
          copy_scalar(yaml_document_get_node(doc, field->value), value, sizeof(value)) != QSR_OK) {
        return QSR_ERR_INVALID;
      }
      unsigned bit;
      qsr_status_t status;
      if (strcmp(name, "id") == 0) {
        bit = 1;
        status = parse_size(value, 0, 6, &rotation);
      } else if (strcmp(name, "serverIdLength") == 0) {
        bit = 2;
        status = parse_size(value, 1, QSR_QUIC_LB_MAX_SERVER_ID, &sid_len);
      } else if (strcmp(name, "nonceLength") == 0) {
        bit = 4;
        status = parse_size(value, 4, 18, &nonce_len);
      } else if (strcmp(name, "key") == 0) {
        bit = 8;
        status = qsr_cid_codec_init_from_hex(&parsed_key, value);
      } else {
        return QSR_ERR_INVALID;
      }
      if (status != QSR_OK || (seen & bit) != 0) {
        return QSR_ERR_INVALID;
      }
      seen |= bit;
    }
    if ((seen & 7U) != 7U || qsr_quic_lb_config_init(lb, (uint8_t)rotation, (uint8_t)sid_len, (uint8_t)nonce_len,
                                                    parsed_key.enabled ? parsed_key.key : nullptr) != QSR_OK) {
      return QSR_ERR_INVALID;
    }
  }
  return QSR_OK;
}

[[nodiscard]] static qsr_status_t parse_root(yaml_document_t *doc, qsr_config_t *config) {
  yaml_node_t *root = yaml_document_get_root_node(doc);
  if (root == nullptr) {
    /* Empty document — caller already has defaults. */
    return QSR_OK;
  }
  if (root->type != YAML_MAPPING_NODE) {
    return QSR_ERR_INVALID;
  }
  for (yaml_node_pair_t *pair = root->data.mapping.pairs.start; pair < root->data.mapping.pairs.top; pair++) {
    yaml_node_t *k = yaml_document_get_node(doc, pair->key);
    yaml_node_t *v = yaml_document_get_node(doc, pair->value);
    char key[16];
    qsr_status_t status = copy_scalar(k, key, sizeof(key));
    if (status != QSR_OK) {
      return status;
    }
    if (strcmp(key, "listen") == 0) {
      status = parse_listen(doc, v, config);
    } else if (strcmp(key, "sessions") == 0) {
      status = parse_sessions(doc, v, config);
    } else if (strcmp(key, "routes") == 0) {
      status = parse_routes(doc, v, config);
    } else if (strcmp(key, "cidEncoding") == 0) {
      status = parse_cid_encoding(doc, v, config);
    } else if (strcmp(key, "quicLb") == 0) {
      status = parse_quic_lb(doc, v, &config->quic_lb);
    } else if (strcmp(key, "logging") == 0) {
      status = parse_logging(doc, v, config);
    } else {
      return QSR_ERR_INVALID;
    }
    if (status != QSR_OK) {
      return status;
    }
  }
  if (config->quic_lb.enabled && config->cid_codec.enabled) {
    return QSR_ERR_INVALID; /* Formats overlap: never guess which codec owns a CID. */
  }
  bool mapped[QSR_QUIC_LB_CONFIGS] = {false};
  for (size_t r = 0; r < config->routes.count; r++) {
    const qsr_route_t *route = &config->routes.routes[r];
    if (config->quic_lb.enabled && route->server_id != 0) {
      return QSR_ERR_INVALID;
    }
    for (size_t c = 0; c < QSR_QUIC_LB_CONFIGS; c++) {
      const uint8_t len = route->quic_lb_ids[c].len;
      if (len != 0) {
        if (!config->quic_lb.configs[c].active || len != config->quic_lb.configs[c].server_id_len) {
          return QSR_ERR_INVALID;
        }
        mapped[c] = true;
      }
    }
  }
  for (size_t c = 0; c < QSR_QUIC_LB_CONFIGS; c++) {
    if (config->quic_lb.configs[c].active && !mapped[c]) {
      return QSR_ERR_INVALID;
    }
  }
  return QSR_OK;
}

qsr_status_t qsr_config_load(const char *path, qsr_config_t *config) {
  if (path == nullptr || config == nullptr) {
    return QSR_ERR_INVALID;
  }
  qsr_config_default(config);

  FILE *file = fopen(path, "re");
  if (file == nullptr) {
    /* cppcheck-suppress resourceLeak ; file is nullptr — nothing to close. */
    return errno == ENOENT ? QSR_ERR_NOT_FOUND : QSR_ERR_INVALID;
  }

  yaml_parser_t parser;
  if (yaml_parser_initialize(&parser) == 0) {
    (void)fclose(file);
    return QSR_ERR_INVALID;
  }
  yaml_parser_set_input_file(&parser, file);

  qsr_status_t status = QSR_OK;
  yaml_document_t document;
  if (yaml_parser_load(&parser, &document) == 0) {
    status = QSR_ERR_INVALID;
  } else {
    status = parse_root(&document, config);
    yaml_document_delete(&document);
  }

  if (status != QSR_OK && parser.problem != nullptr) {
    (void)fprintf(stderr, "config %s:%zu:%zu: %s\n", path, parser.problem_mark.line + 1U,
                  parser.problem_mark.column + 1U, parser.problem);
  }

  yaml_parser_delete(&parser);
  (void)fclose(file);
  return status;
}
