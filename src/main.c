#include "qsr/config.h"
#include "qsr/hash.h"
#include "qsr/udp.h"

#include <stdio.h>
#include <string.h>

static const char *status_name(qsr_status_t status) {
  switch (status) {
    case QSR_OK:
      return "ok";
    case QSR_ERR_INVALID:
      return "invalid";
    case QSR_ERR_TRUNCATED:
      return "truncated";
    case QSR_ERR_UNSUPPORTED:
      return "unsupported";
    case QSR_ERR_NOT_FOUND:
      return "not_found";
    case QSR_ERR_FULL:
      return "full";
  }
  return "unknown";
}

int main(int argc, char **argv) {
  /*
   * Seed the SipHash key from getrandom before anything else hashes anything.
   * The route and session tables use this; without it they'd lazy-init on
   * first use, which is fine for tests but worth doing eagerly at startup
   * so a getrandom failure surfaces before we start serving traffic.
   */
  if (qsr_hash_init() != QSR_OK) {
    (void)fprintf(stderr, "failed to seed hash key\n");
    return 1;
  }

  qsr_config_t config;
  qsr_status_t status = QSR_OK;
  if (argc > 2) {
    (void)fprintf(stderr, "usage: %s [config.yaml]\n", argv[0]);
    return 2;
  }
  const char *config_path = nullptr;
  if (argc == 2) {
    config_path = argv[1];
    status = qsr_config_load(config_path, &config);
  } else {
    qsr_config_default(&config);
  }
  if (status != QSR_OK) {
    (void)fprintf(stderr, "failed to load config: %s\n", status_name(status));
    return 1;
  }
  status = qsr_udp_run(&config, config_path);
  return status == QSR_OK ? 0 : 1;
}
