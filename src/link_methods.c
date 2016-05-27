#include "src/link_methods.h"
#include "src/common.h"
#include "src/private.h"
#include "src/queue.h"

static int uv_ssl_read_start(uv_link_t* link);
static int uv_ssl_read_stop(uv_link_t* link);
static int uv_ssl_write(uv_link_t* link, uv_link_t* source,
                        const uv_buf_t bufs[], unsigned int nbufs,
                        uv_stream_t* send_handle, uv_link_write_cb cb,
                        void* arg);
static int uv_ssl_try_write(uv_link_t* link,
                            const uv_buf_t bufs[],
                            unsigned int nbufs);
static int uv_ssl_shutdown(uv_link_t* link, uv_link_t* source,
                           uv_link_shutdown_cb cb, void* arg);
static void uv_ssl_alloc_cb_override(uv_link_t* link,
                                     size_t suggested_size,
                                     uv_buf_t* buf);
static void uv_ssl_read_cb_override(uv_link_t* link,
                                    ssize_t nread,
                                    const uv_buf_t* buf);

uv_link_methods_t uv_ssl_methods = {
  .read_start = uv_ssl_read_start,
  .read_stop = uv_ssl_read_stop,

  .write = uv_ssl_write,
  .try_write = uv_ssl_try_write,

  .shutdown = uv_ssl_shutdown,

  .alloc_cb_override = uv_ssl_alloc_cb_override,
  .read_cb_override = uv_ssl_read_cb_override
};


int uv_ssl_read_start(uv_link_t* link) {
  uv_ssl_t* ssl;
  int internal;

  ssl = container_of(link, uv_ssl_t, link);

  uv_ssl_cycle(ssl);
  internal = ssl->reading == kSSLReadingHandshake;
  ssl->reading = kSSLReadingData;

  /* Already reading, skip calling parent */
  if (internal)
    return 0;

  return uv_link_read_start(link->parent);
}


int uv_ssl_read_stop(uv_link_t* link) {
  uv_ssl_t* ssl;

  ssl = container_of(link, uv_ssl_t, link);
  ssl->reading = kSSLReadingNone;

  return uv_link_read_stop(link->parent);
}


int uv_ssl_write(uv_link_t* link,
                 uv_link_t* source,
                 const uv_buf_t bufs[],
                 unsigned int nbufs,
                 uv_stream_t* send_handle,
                 uv_link_write_cb cb,
                 void* arg) {
  uv_ssl_t* ssl;
  unsigned int i;
  unsigned int j;
  char* p;
  size_t extra_size;
  uv_ssl_write_t* req;
  int err;
  int bytes;

  ssl = container_of(link, uv_ssl_t, link);

  bytes = 0;
  for (i = 0; i < nbufs; i++) {
    bytes = SSL_write(ssl->ssl, bufs[i].base, bufs[i].len);
    if (bytes == -1)
      break;

    CHECK_EQ(bytes, (int) bufs[i].len,
             "SSL_write() does not do partial writes");
  }

  /* All written immediately */
  if (i == nbufs) {
    err = uv_ssl_queue_write_cb(ssl, source, cb, arg);
    if (err != 0)
      return err;

    return uv_ssl_cycle(ssl);
  }

  err = nbufs != 0 ? SSL_get_error(ssl->ssl, bytes) : 0;
  if (err == SSL_ERROR_WANT_READ ||
      err == SSL_ERROR_WANT_WRITE ||
      err == SSL_ERROR_WANT_X509_LOOKUP) {
    err = 0;
  } else if (err != 0) {
    return UV_EPROTO;
  }

  /* Only buffers before `i` were written, queue rest */
  extra_size = 0;
  for (j = 0; j <= i; j++)
    extra_size += bufs[i].len;

  req = malloc(sizeof(*req) + extra_size);
  if (req == NULL)
    return UV_ENOMEM;

  for (j = 0, p = uv_ssl_write_data(req); j <= i; j++, p += bufs[i].len)
    memcpy(p, bufs[i].base, bufs[i].len);

  req->link = link;
  req->source = source;
  req->size = extra_size;
  req->send_handle = send_handle;
  req->cb = cb;
  req->arg = arg;

  QUEUE_INSERT_TAIL(&ssl->write_queue, &req->member);

  return uv_ssl_cycle(ssl);
}


int uv_ssl_try_write(uv_link_t* link,
                     const uv_buf_t bufs[],
                     unsigned int nbufs) {
  uv_ssl_t* ssl;
  unsigned int i;
  size_t total;
  int bytes;
  int err;

  ssl = container_of(link, uv_ssl_t, link);

  total = 0;
  for (i = 0; i < nbufs; i++) {
    bytes = SSL_write(ssl->ssl, bufs[i].base, bufs[i].len);
    if (bytes == -1)
      break;

    CHECK_EQ(bytes, (int) bufs[i].len,
             "SSL_write() does not do partial writes");
    total += bytes;
  }

  err = nbufs != 0 ? SSL_get_error(ssl->ssl, bytes) : 0;
  if (err == SSL_ERROR_WANT_READ ||
      err == SSL_ERROR_WANT_WRITE ||
      err == SSL_ERROR_WANT_X509_LOOKUP) {
    err = 0;
  } else if (err != 0) {
    return UV_EPROTO;
  }

  err = uv_ssl_cycle(ssl);
  if (err != 0)
    return err;

  return total;
}


int uv_ssl_shutdown(uv_link_t* link, uv_link_t* source,
                    uv_link_shutdown_cb cb,
                    void* arg) {
  /* TODO(indutny): SSL_shutdown() */
  return uv_link_shutdown(link->parent, source, cb, arg);
}


void uv_ssl_alloc_cb_override(uv_link_t* link,
                              size_t suggested_size,
                              uv_buf_t* buf) {
  uv_ssl_t* ssl;
  size_t avail;
  char* ptr;

  ssl = container_of(link, uv_ssl_t, link);

  avail = 0;
  ptr = ringbuffer_write_ptr(&ssl->encrypted.input, &avail);
  *buf = uv_buf_init(ptr, avail);
}


void uv_ssl_read_cb_override(uv_link_t* link,
                             ssize_t nread,
                             const uv_buf_t* buf) {
  int r;
  uv_ssl_t* ssl;

  ssl = container_of(link, uv_ssl_t, link);

  /* TODO(indutny): handle error */
  if (ssl->reading == kSSLReadingNone)
    uv_link_read_stop(link->parent);

  /* Commit data if there was no error */
  r = 0;
  if (nread >= 0)
    r = ringbuffer_write_append(&ssl->encrypted.input, nread);

  /* Handle EOF */
  if (nread == UV_EOF) {
    /* TODO(indutny): handle error */
    uv_link_read_stop(link);
    return;
  }

  /* TODO(indutny): handle error */
  uv_ssl_cycle(ssl);
}
