#ifndef QSR_TEST_MAIN_H
#define QSR_TEST_MAIN_H

#include <stdio.h>
#include <stdlib.h>

#define ASSERT_TRUE(expr)                                                                                              \
  do {                                                                                                                 \
    if (!(expr)) {                                                                                                     \
      fprintf(stderr, "assertion failed: %s:%d: %s\n", __FILE__, __LINE__, #expr);                                    \
      abort();                                                                                                         \
    }                                                                                                                  \
  } while (0)

#endif
