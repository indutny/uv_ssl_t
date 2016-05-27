#include <stdlib.h>
#include <string.h>

#include "src/common.h"
#include "src/bio.h"
#include "src/link_methods.h"

static void uv_ssl_check_close_cb(uv_handle_t* handle);
static int uv_ssl_cycle_input(uv_ssl_t* s);
static int uv_ssl_cycle_output(uv_ssl_t* s);
static int uv_ssl_cycle_pending(uv_ssl_t* s);
static int uv_ssl_handshake_read_start(uv_ssl_t* s);
static int uv_ssl_handshake_read_stop(uv_ssl_t* s);
static void uv_ssl_write_cb(uv_link_t* link, int status);

uv_ssl_t* uv_ssl_create(uv_loop_t* loop, SSL* ssl, int* err) {
  uv_ssl_t* res;
  BIO* rbio;
  BIO* wbio;

  res = calloc(1, sizeof(*res));
  if (res == NULL) {
    *err = UV_ENOMEM;
    return res;
  }

  QUEUE_INIT(&res->write_queue);
  QUEUE_INIT(&res->write_cb_queue);

  ringbuffer_init(&res->encrypted.input);
  ringbuffer_init(&res->encrypted.output);

  *err = uv_link_init(&res->link, &uv_ssl_methods);
  if (*err != 0)
    goto fail;

  res->ssl = ssl;
  rbio = uv_ssl_bio_new(&res->encrypted.input);
  wbio = uv_ssl_bio_new(&res->encrypted.output);
  if (rbio == NULL || wbio == NULL) {
    *err = UV_ENOMEM;
    goto fail_bio;
  }

  SSL_set_bio(res->ssl, rbio, wbio);
  rbio = NULL;
  wbio = NULL;

  *err = uv_check_init(loop, &res->write_cb_check);
  if (*err != 0)
    goto fail_bio;

  return res;

fail_bio:
  if (rbio != NULL)
    BIO_free_all(rbio);
  if (wbio != NULL)
    BIO_free_all(wbio);

  uv_link_close(&res->link);

fail:
  free(res);
  return NULL;
}


void uv_ssl_check_close_cb(uv_handle_t* handle) {
  uv_ssl_t* ssl;

  ssl = container_of(handle, uv_ssl_t, write_cb_check);

  free(ssl);
}


void uv_ssl_destroy(uv_ssl_t* s) {
  ringbuffer_destroy(&s->encrypted.input);
  ringbuffer_destroy(&s->encrypted.output);

  /* NOTE: User is resposible for disposing ssl */
  s->ssl = NULL;
  uv_link_close(&s->link);
  uv_close((uv_handle_t*) &s->write_cb_check, uv_ssl_check_close_cb);
}


uv_link_t* uv_ssl_get_link(uv_ssl_t* s) {
  return &s->link;
}


int uv_ssl_cycle(uv_ssl_t* s) {
  int err;

  if (s->cycle != 0)
    return 0;

  s->cycle = 1;

  /* TODO(indutny): kill connection on error */
  err = uv_ssl_cycle_input(s);
  if (err == 0)
    err = uv_ssl_cycle_pending(s);
  if (err == 0)
    err = uv_ssl_cycle_output(s);

  s->cycle = 0;

  return err;
}


int uv_ssl_handshake_read_start(uv_ssl_t* s) {
  s->reading = kSSLReadingHandshake;
  return uv_link_read_start(s->link.parent);
}


int uv_ssl_handshake_read_stop(uv_ssl_t* s) {
  s->reading = kSSLReadingNone;
  return uv_link_read_stop(s->link.parent);
}


int uv_ssl_cycle_input(uv_ssl_t* s) {
  static const size_t kSuggestedSize = 16 * 1024;
  uv_buf_t buf;
  int bytes;
  int err;

  err = 0;

  if (s->reading == kSSLReadingData) {
    /* Reads were requested */
    do {
      uv_link_propagate_alloc_cb(&s->link, kSuggestedSize, &buf);
      if (buf.len == 0) {
        uv_link_propagate_read_cb(&s->link, UV_ENOBUFS, &buf);
        return -1;
      }

      bytes = SSL_read(s->ssl, buf.base, buf.len);
      if (bytes <= 0)
        break;

      uv_link_propagate_read_cb(&s->link, bytes, &buf);
    } while (bytes > 0);

    err = SSL_get_error(s->ssl, bytes);
  } else if (!SSL_is_init_finished(s->ssl)) {
    /* No reads were requested, just perform handshake */
    if (SSL_is_server(s->ssl))
      err = SSL_accept(s->ssl);
    else
      err = SSL_connect(s->ssl);

    if (err <= 0)
      err = SSL_get_error(s->ssl, err);
    else
      err = 0;
  }

  /* Start reading if asked during handshake */
  if (err == SSL_ERROR_WANT_READ &&
      s->reading == kSSLReadingNone &&
      !SSL_is_init_finished(s->ssl)) {
    err = uv_ssl_handshake_read_start(s);
  } else if (err == SSL_ERROR_WANT_READ ||
             err == SSL_ERROR_WANT_WRITE ||
             err == SSL_ERROR_WANT_X509_LOOKUP) {
    err = 0;
  } else if (err != 0) {
    /* TODO(indutny): meaningful errors */
    err = UV_EPROTO;
  }

  /* Stop reading after handshake */
  if (err == 0 &&
      s->reading == kSSLReadingHandshake &&
      SSL_is_init_finished(s->ssl)) {
    err = uv_ssl_handshake_read_stop(s);
  }

  if (s->reading == kSSLReadingData)
    uv_link_propagate_read_cb(&s->link, err, &buf);

  return err;
}


int uv_ssl_cycle_pending(uv_ssl_t* s) {
  QUEUE write_queue;
  QUEUE* q;
  QUEUE* next;
  int err;

  /* Writes won't succeed until handshake end */
  if (!SSL_is_init_finished(s->ssl))
    return 0;

  QUEUE_MOVE(&s->write_queue, &write_queue);
  QUEUE_INIT(&s->write_queue);

  for (q = QUEUE_HEAD(&write_queue); q != &write_queue; q = next) {
    uv_ssl_write_t* req;
    uv_buf_t buf;

    next = QUEUE_NEXT(q);
    req = QUEUE_DATA(q, uv_ssl_write_t, member);

    buf = uv_buf_init(uv_ssl_write_data(req), req->size);
    err = uv_link_write(req->link, req->source, &buf, 1, req->send_handle,
                        req->cb);
    free(req);

    if (err != 0)
      return err;
  }

  return 0;
}


int uv_ssl_cycle_output(uv_ssl_t* s) {
  size_t avail;
  char* out[RING_BUFFER_COUNT];
  uv_buf_t buf[RING_BUFFER_COUNT];
  size_t size[ARRAY_SIZE(out)];
  size_t count;
  size_t i;
  int err;

  count = ARRAY_SIZE(out);
  avail = ringbuffer_read_nextv(&s->encrypted.output, out, size, &count);
  if (avail == 0)
    return 0;

  for (i = 0; i < count; i++)
    buf[i] = uv_buf_init(out[i], size[i]);

  /* TODO(indutny): try_write first */

  err = uv_link_write(s->link.parent, &s->link, buf, count, NULL,
                      uv_ssl_write_cb);
  if (err != 0)
    return err;

  /* Consume data that was sent */
  ringbuffer_read_skip(&s->encrypted.output, avail);

  return 0;
}


void uv_ssl_write_cb(uv_link_t* link, int status) {
  uv_ssl_t* s;

  s = container_of(link, uv_ssl_t, link);

  /* TODO(indutny): kill connection on error */

  uv_ssl_cycle(s);
}


void uv_ssl_flush_write_cb(uv_check_t* handle) {
  uv_ssl_t* ssl;
  QUEUE write_cb_queue;
  QUEUE* q;
  QUEUE* next;

  CHECK_EQ(uv_check_stop(handle), 0, "uv_check_stop() can't fail");

  ssl = container_of(handle, uv_ssl_t, write_cb_check);

  QUEUE_MOVE(&ssl->write_cb_queue, &write_cb_queue);
  QUEUE_INIT(&ssl->write_cb_queue);

  for (q = QUEUE_HEAD(&write_cb_queue); q != &write_cb_queue; q = next) {
    uv_ssl_write_cb_t* req;

    next = QUEUE_NEXT(q);
    req = QUEUE_DATA(q, uv_ssl_write_cb_t, member);

    req->cb(req->source, 0);
    free(req);
  }
}


int uv_ssl_queue_write_cb(uv_ssl_t* ssl, uv_link_t* source,
                          uv_link_write_cb cb) {
  uv_ssl_write_cb_t* req;

  req = malloc(sizeof(*req));
  if (req == NULL)
    return UV_ENOMEM;

  req->source = source;
  req->cb = cb;

  QUEUE_INSERT_TAIL(&ssl->write_cb_queue, &req->member);

  if (!uv_is_active((uv_handle_t*) &ssl->write_cb_check))
    return uv_check_start(&ssl->write_cb_check, uv_ssl_flush_write_cb);

  return 0;
}
