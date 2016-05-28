/*
 * **************************************************************************
 * *****                         WARNING !!                             *****
 * *****                                                                *****
 * ***** This is by no means an example of **secure** OpenSSL server    *****
 * *****             Do not use this code in production.                *****
 * **************************************************************************
 */


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

#include "uv.h"
#include "uv_link_t.h"
#include "uv_ssl_t.h"

/* Declaration of `middle_methods` */
#include "middle.h"

typedef struct client_s client_t;

static uv_tcp_t server;
static SSL_CTX* ctx;

struct client_s {
  uv_tcp_t tcp;
  SSL* ssl;
  uv_link_source_t source;
  uv_ssl_t* ssl_link;
  uv_link_t middle;
  uv_link_observer_t observer;
};

static void close_cb(uv_link_t* link) {
  client_t* client;

  client = link->data;
  free(client);
}

static void read_cb(uv_link_observer_t* observer,
                    ssize_t nread,
                    const uv_buf_t* buf) {
  client_t* client;

  client = observer->link.data;

  if (nread < 0) {
    fprintf(stderr, "error or close\n");
    uv_link_close(&observer->link, close_cb);
    return;
  }

  fprintf(stderr, "read \"%.*s\"\n", (int) nread, buf->base);
}


static void connection_cb(uv_stream_t* s, int status) {
  int err;
  client_t* client;

  client = malloc(sizeof(*client));
  assert(client != NULL);

  client->ssl = SSL_new(ctx);
  assert(client->ssl != NULL);

  SSL_set_accept_state(client->ssl);

  err = uv_tcp_init(uv_default_loop(), &client->tcp);
  assert(err == 0);

  err = uv_accept(s, (uv_stream_t*) &client->tcp);
  assert(err == 0);

  err = uv_link_source_init(&client->source, (uv_stream_t*) &client->tcp);
  assert(err == 0);

  client->ssl_link = uv_ssl_create(uv_default_loop(), client->ssl, &err);
  assert(client->ssl_link != NULL && err == 0);

  err = uv_link_chain(&client->source.link, uv_ssl_get_link(client->ssl_link));
  assert(err == 0);

  err = uv_link_init(&client->middle, &middle_methods);
  assert(err == 0);

  err = uv_link_chain(uv_ssl_get_link(client->ssl_link), &client->middle);
  assert(err == 0);

  err = uv_link_observer_init(&client->observer);
  assert(err == 0);

  err = uv_link_chain(&client->middle, &client->observer.link);
  assert(err == 0);

  client->observer.read_cb = read_cb;
  client->observer.link.data = client;

  err = uv_link_read_start(&client->observer.link);
  assert(err == 0);
}


int main() {
  static const int kBacklog = 128;

  int err;
  uv_loop_t* loop;
  struct sockaddr_in addr;

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_digests();
  SSL_load_error_strings();
  ERR_load_crypto_strings();

  /* Initialize SSL_CTX */
  ctx = SSL_CTX_new(SSLv23_method());
  assert(ctx != NULL);

  SSL_CTX_use_certificate_file(ctx, "test/keys/cert.pem", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "test/keys/key.pem", SSL_FILETYPE_PEM);

  loop = uv_default_loop();

  err = uv_tcp_init(loop, &server);
  assert(err == 0);

  err = uv_ip4_addr("0.0.0.0", 9000, &addr);
  assert(err == 0);

  err = uv_tcp_bind(&server, (struct sockaddr*) &addr, 0);
  assert(err == 0);

  fprintf(stderr, "Listening on 0.0.0.0:9000\n");

  err = uv_listen((uv_stream_t*) &server, kBacklog, connection_cb);

  err = uv_run(loop, UV_RUN_DEFAULT);
  assert(err == 0);

  return 0;
}
