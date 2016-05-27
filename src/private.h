#ifndef SRC_PRIVATE_H_
#define SRC_PRIVATE_H_

#include "openssl/ssl.h"
#include "ringbuffer.h"
#include "uv_link_t.h"

#include "src/queue.h"

typedef struct uv_ssl_write_req_s uv_ssl_write_req_t;
typedef struct uv_ssl_write_cb_wrap_s uv_ssl_write_cb_wrap_t;

enum uv_ssl_reading_e {
  /* Initial state, or reads are stopped after handshake */
  kSSLReadingNone,

  /* When reading without `uv_link_read_start()` during handshake */
  kSSLReadingHandshake,

  /* When reading with `uv_link_read_start()` */
  kSSLReadingData
};
typedef enum uv_ssl_reading_e uv_ssl_reading_t;

struct uv_ssl_s {
  uv_link_t link;

  SSL* ssl;
  uv_check_t write_cb_check;

  uv_ssl_reading_t reading;
  unsigned int cycle:1;
  QUEUE write_queue;
  QUEUE write_cb_queue;

  struct {
    ringbuffer input;
    ringbuffer output;
  } encrypted;
};

struct uv_ssl_write_req_s {
  QUEUE member;

  uv_link_t* link;
  uv_link_t* source;
  size_t size;
  uv_stream_t* send_handle;
  uv_link_write_cb cb;
  void* arg;
};

struct uv_ssl_write_cb_wrap_s {
  QUEUE member;

  uv_link_t* source;
  uv_link_write_cb cb;
  void* arg;
};

int uv_ssl_cycle(uv_ssl_t* ssl);
int uv_ssl_queue_write_cb(uv_ssl_t* ssl, uv_link_t* source,
                          uv_link_write_cb cb, void* arg);

static char* uv_ssl_write_data(uv_ssl_write_req_t* req) {
  return (char*) req + sizeof(*req);
}

#endif  /* SRC_PRIVATE_H_ */
