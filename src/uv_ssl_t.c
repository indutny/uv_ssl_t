#include <stdlib.h>
#include <string.h>

#include "src/common.h"
#include "src/bio.h"
#include "src/link_methods.h"

static void uv_ssl_init_close_cb(uv_handle_t* handle);
static void uv_ssl_idle_close_cb(uv_handle_t* handle);
static int uv_ssl_cycle_input(uv_ssl_t* s);
static int uv_ssl_cycle_output(uv_ssl_t* s);
static int uv_ssl_cycle_pending(uv_ssl_t* s);
static int uv_ssl_handshake_read_start(uv_ssl_t* s);
static int uv_ssl_handshake_read_stop(uv_ssl_t* s);
static void uv_ssl_write_cb(uv_link_t* link, int status, void* arg);
static int uv_ssl_queue_write_cb(uv_ssl_t* ssl, uv_link_t* source,
                                 uv_link_write_cb cb, void* arg);
static void uv_ssl_flush_write_cb(uv_idle_t* handle);
static char* uv_ssl_get_write_data(uv_ssl_write_req_t* req);

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

  *err = uv_idle_init(loop, &res->write_cb_idle);
  if (*err != 0)
    goto fail_bio;

  *err = uv_link_init((uv_link_t*) res, &uv_ssl_methods);
  if (*err != 0)
    goto fail_link_init;

  return res;

fail_link_init:
  ringbuffer_destroy(&res->encrypted.input);
  ringbuffer_destroy(&res->encrypted.output);
  uv_close((uv_handle_t*) &res->write_cb_idle, uv_ssl_init_close_cb);
  return NULL;

fail_bio:
  ringbuffer_destroy(&res->encrypted.input);
  ringbuffer_destroy(&res->encrypted.output);

  if (rbio != NULL)
    BIO_free_all(rbio);
  if (wbio != NULL)
    BIO_free_all(wbio);

  free(res);
  return NULL;
}


void uv_ssl_init_close_cb(uv_handle_t* handle) {
  uv_ssl_t* ssl;

  ssl = container_of(handle, uv_ssl_t, write_cb_idle);

  free(ssl);
}


void uv_ssl_idle_close_cb(uv_handle_t* handle) {
  uv_ssl_t* ssl;
  uv_link_t* source;
  uv_link_close_cb close_cb;

  ssl = container_of(handle, uv_ssl_t, write_cb_idle);

  source = ssl->close_source;
  close_cb = ssl->close_cb;

  ringbuffer_destroy(&ssl->encrypted.input);
  ringbuffer_destroy(&ssl->encrypted.output);

  close_cb(source);
  free(ssl);
}


void uv_ssl_destroy(uv_ssl_t* s, uv_link_t* source, uv_link_close_cb cb) {
  /* NOTE: User is resposible for disposing ssl */
  s->ssl = NULL;
  s->close_source = source;
  s->close_cb = cb;
  uv_close((uv_handle_t*) &s->write_cb_idle, uv_ssl_idle_close_cb);
}


int uv_ssl_cycle(uv_ssl_t* s) {
  int err;

  /* Destroyed */
  if (s->ssl == NULL)
    return 0;

  err = uv_ssl_pop_error(s);
  if (err != 0)
    return err;

  if (s->cycle != 0)
    return 0;

  s->cycle = 1;

  err = uv_ssl_cycle_input(s);
  if (err == 0)
    err = uv_ssl_cycle_pending(s);
  if (err == 0)
    err = uv_ssl_cycle_output(s);

  s->cycle = 0;

  return err;
}


int uv_ssl_handshake_read_start(uv_ssl_t* s) {
  s->state = kSSLStateHandshake;
  return uv_link_read_start(s->parent);
}


int uv_ssl_handshake_read_stop(uv_ssl_t* s) {
  s->state = kSSLStateNone;
  return uv_link_read_stop(s->parent);
}


int uv_ssl_cycle_input(uv_ssl_t* s) {
  static const size_t kSuggestedSize = 16 * 1024;
  uv_buf_t buf;
  int bytes;
  int err;
  int needs_read;

  err = 0;
  needs_read = 0;

  if (s->state == kSSLStateData) {
    /* Reads were requested */
    do {
      uv_link_propagate_alloc_cb((uv_link_t*) s, kSuggestedSize, &buf);
      if (buf.len == 0) {
        uv_link_propagate_read_cb((uv_link_t*) s, UV_ENOBUFS, &buf);
        return -1;
      }

      needs_read = 1;
      bytes = SSL_read(s->ssl, buf.base, buf.len);
      if (bytes <= 0)
        break;

      needs_read = 0;
      uv_link_propagate_read_cb((uv_link_t*) s, bytes, &buf);

      /* Freed in the middle */
      if (s->ssl == NULL)
        return 0;
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

  /* Start state if asked during handshake */
  if (err == SSL_ERROR_WANT_READ &&
      s->state == kSSLStateNone &&
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

  /* Stop state after handshake */
  if (err == 0 &&
      s->state == kSSLStateHandshake &&
      SSL_is_init_finished(s->ssl)) {
    err = uv_ssl_handshake_read_stop(s);
  }

  if (needs_read) {
    needs_read = 0;
    uv_link_propagate_read_cb((uv_link_t*) s, err, &buf);
    /* Do not double-report error */
    if (err != 0)
      s->state = kSSLStateError;
    return err;
  }

  return err;
}


int uv_ssl_cycle_pending(uv_ssl_t* s) {
  QUEUE write_queue;
  QUEUE* q;
  QUEUE* next;
  int err;

  /* Destroyed */
  if (s->ssl == NULL)
    return 0;

  /* Writes won't succeed until handshake end */
  if (!SSL_is_init_finished(s->ssl))
    return 0;

  QUEUE_MOVE(&s->write_queue, &write_queue);
  QUEUE_INIT(&s->write_queue);

  for (q = QUEUE_HEAD(&write_queue); q != &write_queue; q = next) {
    uv_ssl_write_req_t* req;
    uv_buf_t buf;

    next = QUEUE_NEXT(q);
    req = QUEUE_DATA(q, uv_ssl_write_req_t, member);

    buf = uv_buf_init(uv_ssl_get_write_data(req), req->size);
    err = uv_link_propagate_write((uv_link_t*) s, req->source, &buf, 1, NULL,
                                  req->cb, req->arg);
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

  /* Destroyed */
  if (s->ssl == NULL)
    return 0;

restart:
  count = ARRAY_SIZE(out);
  avail = ringbuffer_read_nextv(&s->encrypted.output, out, size, &count);
  if (avail == 0)
    return 0;

  for (i = 0; i < count; i++)
    buf[i] = uv_buf_init(out[i], size[i]);

  err = uv_link_try_write(s->parent, buf, count);

  /* Skip written bytes */
  if (err > 0)
    ringbuffer_read_skip(&s->encrypted.output, err);

  /* Wrote everything at once */
  if (err == (int) avail)
    goto restart;

  /* No support for try_write */
  if (err == UV_ENOSYS || err == UV_EAGAIN)
    err = 0;
  /* Real error */
  else if (err < 0)
    return err;

  /* Reload buffers */
  count = ARRAY_SIZE(out);
  avail = ringbuffer_read_nextv(&s->encrypted.output, out, size, &count);
  if (avail == 0)
    return 0;

  for (i = 0; i < count; i++)
    buf[i] = uv_buf_init(out[i], size[i]);

  /* Write the reset asynchronously */
  err = uv_link_propagate_write(s->parent, (uv_link_t*) s, buf, count, NULL,
                                uv_ssl_write_cb, (void*) (uintptr_t) avail);
  if (err != 0)
    return err;

  /* Consume data that was sent */
  ringbuffer_read_skip(&s->encrypted.output, avail);
  s->pending_write += avail;

  return 0;
}


void uv_ssl_write_cb(uv_link_t* link, int status, void* arg) {
  uv_ssl_t* s;
  int err;
  uintptr_t write_size;

  s = (uv_ssl_t*) link;
  write_size = (uintptr_t) arg;

  err = uv_ssl_cycle(s);
  if (err != 0)
    return uv_ssl_error(s, err, "uv_ssl_write_cb");

  s->pending_write -= (size_t) write_size;

  uv_ssl_flush_write_cb(&s->write_cb_idle);
}


void uv_ssl_flush_write_cb(uv_idle_t* handle) {
  uv_ssl_t* ssl;
  QUEUE write_cb_queue;
  QUEUE* q;
  QUEUE* next;

  CHECK_EQ(uv_idle_stop(handle), 0, "uv_idle_stop() can't fail");

  ssl = container_of(handle, uv_ssl_t, write_cb_idle);

  QUEUE_MOVE(&ssl->write_cb_queue, &write_cb_queue);
  QUEUE_INIT(&ssl->write_cb_queue);

  for (q = QUEUE_HEAD(&write_cb_queue); q != &write_cb_queue; q = next) {
    uv_ssl_write_cb_wrap_t* wrap;

    next = QUEUE_NEXT(q);
    wrap = QUEUE_DATA(q, uv_ssl_write_cb_wrap_t, member);

    /* Reinsert pending writes */
    if (wrap->pending && ssl->pending_write != 0) {
      QUEUE_INSERT_TAIL(&ssl->write_cb_queue, &wrap->member);
      continue;
    }

    wrap->cb(wrap->source, 0, wrap->arg);
    free(wrap);
  }
}


int uv_ssl_queue_write_cb(uv_ssl_t* ssl, uv_link_t* source,
                          uv_link_write_cb cb, void* arg) {
  uv_ssl_write_cb_wrap_t* wrap;
  int err;

  err = uv_ssl_cycle(ssl);
  if (err != 0)
    return err;

  wrap = malloc(sizeof(*wrap));
  if (wrap == NULL)
    return UV_ENOMEM;

  wrap->source = source;
  wrap->cb = cb;
  wrap->arg = arg;
  wrap->pending = ssl->pending_write != 0;

  QUEUE_INSERT_TAIL(&ssl->write_cb_queue, &wrap->member);

  if (!wrap->pending && !uv_is_active((uv_handle_t*) &ssl->write_cb_idle))
    return uv_idle_start(&ssl->write_cb_idle, uv_ssl_flush_write_cb);

  return 0;
}


char* uv_ssl_get_write_data(uv_ssl_write_req_t* req) {
  return (char*) req + sizeof(*req);
}


int uv_ssl_write(uv_ssl_t* ssl, uv_link_t* source, const uv_buf_t bufs[],
                 unsigned int nbufs, uv_link_write_cb cb, void* arg) {
  unsigned int i;
  unsigned int j;
  char* p;
  size_t extra_size;
  uv_ssl_write_req_t* req;
  int err;
  int bytes;

  err = uv_ssl_pop_error(ssl);
  if (err != 0)
    return err;

  bytes = 0;
  for (i = 0; i < nbufs; i++) {
    bytes = SSL_write(ssl->ssl, bufs[i].base, bufs[i].len);
    if (bytes == -1)
      break;

    CHECK_EQ(bytes, (int) bufs[i].len,
             "SSL_write() does not do partial writes");
  }

  /* All written immediately */
  if (i == nbufs)
    return uv_ssl_queue_write_cb(ssl, source, cb, arg);

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

  for (j = 0, p = uv_ssl_get_write_data(req); j <= i; j++, p += bufs[i].len)
    memcpy(p, bufs[i].base, bufs[i].len);

  req->source = source;
  req->size = extra_size;
  req->cb = cb;
  req->arg = arg;

  QUEUE_INSERT_TAIL(&ssl->write_queue, &req->member);

  return uv_ssl_cycle(ssl);
}


int uv_ssl_sync_write(uv_ssl_t* ssl, const uv_buf_t bufs[],
                      unsigned int nbufs) {
  unsigned int i;
  size_t total;
  int bytes;
  int err;

  err = uv_ssl_pop_error(ssl);
  if (err != 0)
    return err;

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


int uv_ssl_shutdown(uv_ssl_t* ssl, uv_link_t* source, uv_link_shutdown_cb cb,
                    void* arg) {
  int err;

  err = uv_ssl_pop_error(ssl);
  if (err != 0)
    return err;

  if (SSL_shutdown(ssl->ssl) == 0)
    SSL_shutdown(ssl->ssl);

  err = uv_ssl_cycle(ssl);
  if (err != 0)
    return err;

  return uv_link_propagate_shutdown(ssl->parent, source, cb, arg);
}


void uv_ssl_error(uv_ssl_t* ssl, int err, const char* desc) {
  uv_ssl_state_t state;

  state = ssl->state;

  if (state == kSSLStateHandshake)
    uv_ssl_handshake_read_stop(ssl);
  else if (state == kSSLStateData)
    uv_link_read_stop((uv_link_t*) ssl);

  /* Lucky case, user is prepared to handle async error */
  if (state == kSSLStateData)
    return uv_link_propagate_read_cb((uv_link_t*) ssl, err, NULL);

  if (state == kSSLStateError)
    return;

  /* Queue error for later */
  ssl->state = kSSLStateError;
  ssl->pending_err = err;
}


int uv_ssl_pop_error(uv_ssl_t* ssl) {
  int res;

  if (ssl->state != kSSLStateError)
    return 0;

  /* TODO(indutny): Meaningful error? */
  if (ssl->pending_err == 0)
    return UV_EPROTO;

  res = ssl->pending_err;
  ssl->pending_err = 0;
  return res;
}


int uv_ssl_setup_recommended_secure_context(SSL_CTX* ctx) {
  /* ECDHE */
  {
    int nid;
    EC_KEY* ecdh;

    nid = OBJ_sn2nid("prime256v1");
    if (nid == NID_undef)
      return -1;

    ecdh = EC_KEY_new_by_curve_name(nid);
    if (ecdh == NULL)
      return -1;

    /* TODO(indutny): verify return value? */
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);
  }

  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
  SSL_CTX_set_session_cache_mode(ctx,
                                 SSL_SESS_CACHE_SERVER |
                                 SSL_SESS_CACHE_NO_INTERNAL |
                                 SSL_SESS_CACHE_NO_AUTO_CLEAR);
  SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
  SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
  SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
  SSL_CTX_set_cipher_list(ctx,
      "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:"
      "DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:"
      "DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:"
      "ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:"
      "!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA");

  return 0;
}
