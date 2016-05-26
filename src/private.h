#ifndef SRC_PRIVATE_H_
#define SRC_PRIVATE_H_

#include "openssl/ssl.h"
#include "ringbuffer.h"
#include "uv_link_t.h"

struct uv_ssl_s {
  uv_link_t link;

  SSL* ssl;
  size_t writing;

  struct {
    ringbuffer input;
    ringbuffer output;
  } encrypted;
};

void uv_ssl_cycle(uv_ssl_t* ssl);

#endif  /* SRC_PRIVATE_H_ */
