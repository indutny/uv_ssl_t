#include <stdlib.h>
#include <string.h>

#include "src/common.h"
#include "src/bio.h"
#include "src/link_methods.h"

static int uv_ssl_cycle_input(uv_ssl_t* s);
static int uv_ssl_cycle_output(uv_ssl_t* s);
static void uv_ssl_write_cb(uv_link_t* link, int status);

uv_ssl_t* uv_ssl_create(SSL* ssl, int* err) {
  uv_ssl_t* res;
  BIO* rbio;
  BIO* wbio;

  res = calloc(1, sizeof(*res));
  if (res == NULL) {
    *err = UV_ENOMEM;
    return res;
  }

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


void uv_ssl_destroy(uv_ssl_t* s) {
  ringbuffer_destroy(&s->encrypted.input);
  ringbuffer_destroy(&s->encrypted.output);

  /* NOTE: User is resposible for disposing ssl */
  s->ssl = NULL;
  uv_link_close(&s->link);
  free(s);
}


uv_link_t* uv_ssl_get_link(uv_ssl_t* s) {
  return &s->link;
}


void uv_ssl_cycle(uv_ssl_t* s) {
  /* TODO(indutny): kill connection on error */
  if (uv_ssl_cycle_input(s) == 0)
    uv_ssl_cycle_output(s);
}


int uv_ssl_cycle_input(uv_ssl_t* s) {
  static const size_t kSuggestedSize = 16 * 1024;
  uv_buf_t buf;
  int bytes;

  do {
    uv_link_propagate_alloc_cb(&s->link, kSuggestedSize, &buf);
    if (buf.len == 0) {
      uv_link_propagate_read_cb(&s->link, UV_ENOBUFS, &buf);
      return -1;
    }

    bytes = SSL_read(s->ssl, buf.base, buf.len);
  } while (bytes > 0);

  return 0;
}


int uv_ssl_cycle_output(uv_ssl_t* s) {
  size_t avail;
  char* out[RING_BUFFER_COUNT];
  uv_buf_t buf[RING_BUFFER_COUNT];
  size_t size[ARRAY_SIZE(out)];
  size_t count;
  size_t i;

  if (s->writing)
    return 0;

  count = ARRAY_SIZE(out);
  avail = ringbuffer_read_nextv(&s->encrypted.output, out, size, &count);
  if (avail == 0)
    return 0;

  for (i = 0; i < count; i++)
    buf[i] = uv_buf_init(out[i], size[i]);

  /* TODO(indutny): try_write first */

  s->writing = avail;
  return uv_link_write(s->link.parent, &s->link, buf, count, NULL,
                       uv_ssl_write_cb);
}


void uv_ssl_write_cb(uv_link_t* link, int status) {
  uv_ssl_t* s;

  s = container_of(link, uv_ssl_t, link);

  /* TODO(indutny): kill connection on error */
  if (status == 0)
    ringbuffer_read_skip(&s->encrypted.output, s->writing);
  s->writing = 0;

  uv_ssl_cycle(s);
}
