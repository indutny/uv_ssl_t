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

  uv_link_t* source;
  size_t size;
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
int uv_ssl_write(uv_ssl_t* ssl, uv_link_t* source, const uv_buf_t bufs[],
                 unsigned int nbufs, uv_link_write_cb cb, void* arg);
int uv_ssl_sync_write(uv_ssl_t* ssl, const uv_buf_t bufs[],
                      unsigned int nbufs);

#endif  /* SRC_PRIVATE_H_ */
