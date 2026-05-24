#include "qsr/config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <yaml.h>

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

[[nodiscard]] static qsr_status_t parse_route_body(yaml_document_t *doc, yaml_node_t *node, qsr_config_t *config,
                                                   const char *sni) {
  if (node == nullptr || node->type != YAML_MAPPING_NODE) {
    return QSR_ERR_INVALID;
  }
  char host[QSR_MAX_ADDR_LEN + 1U] = {0};
  uint16_t port = 0U;
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
    } else {
      return QSR_ERR_INVALID;
    }
  }
  if (host[0] == '\0' || port == 0U) {
    return QSR_ERR_INVALID;
  }
  return qsr_route_table_add(&config->routes, sni, host, port);
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
    } else {
      return QSR_ERR_INVALID;
    }
    if (status != QSR_OK) {
      return status;
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
