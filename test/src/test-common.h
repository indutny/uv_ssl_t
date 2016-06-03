#ifndef TEST_SRC_TEST_COMMON_H_
#define TEST_SRC_TEST_COMMON_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

#include "uv.h"
#include "uv_ssl_t.h"

#include "test-list.h"

static int fds[2];
static uv_loop_t* loop;
static int close_cb_called;

static struct {
  uv_pipe_t pipe;
  uv_link_source_t source;
  uv_link_observer_t observer;
  uv_ssl_t* ssl_link;
  SSL_CTX* ssl_ctx;
  SSL* ssl;
  int closed;
} server;


static struct {
  SSL* ssl;
  SSL_CTX* ssl_ctx;
  uv_thread_t thread;
} client;


#define CHECK(VALUE, MESSAGE)                                                \
    do {                                                                     \
      if ((VALUE)) break;                                                    \
      fprintf(stderr, "Assertion failure: " #MESSAGE "\n");                  \
      abort();                                                               \
    } while (0)

#define CHECK_EQ(A, B, MESSAGE) CHECK((A) == (B), MESSAGE)
#define CHECK_NE(A, B, MESSAGE) CHECK((A) != (B), MESSAGE)


static void client_thread_body(void* arg) {
  int err;
  void (*fn)(void);

  fn = arg;

  err = SSL_connect(client.ssl);
  if (err != 1)
    goto fail;

  fn();

  return;

fail:
  ERR_print_errors_fp(stderr);
  CHECK(0, "SSL_connect() != 0");
}


static void common_close_cb(uv_link_t* link) {
  close_cb_called++;
}


static void ssl_client_server_test(void (*client_fn)(void),
                                   void (*server_fn)(void)) {
  int err;

  CHECK_NE(loop = uv_default_loop(), NULL, "uv_default_loop()");
  CHECK_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0, "socketpair()");

  /* Initialize source */

  CHECK_EQ(uv_pipe_init(loop, &server.pipe, 0), 0, "uv_pipe_init(server.pipe)");
  CHECK_EQ(uv_pipe_open(&server.pipe, fds[1]), 0, "uv_pipe_open(server.pipe)");

  CHECK_EQ(uv_link_source_init(&server.source, (uv_stream_t*) &server.pipe), 0,
           "uv_link_source_init(server.source)");

  /* Initialize SSL_CTX */

  CHECK_NE(client.ssl_ctx = SSL_CTX_new(TLSv1_2_method()), NULL, "SSL_CTX_new");
  CHECK_NE(server.ssl_ctx = SSL_CTX_new(TLSv1_2_method()), NULL, "SSL_CTX_new");

  CHECK_EQ(SSL_CTX_use_certificate_file(
               server.ssl_ctx, "test/keys/cert.pem", SSL_FILETYPE_PEM),
           1,
           "SSL_CTX_use_certificate_file");
  CHECK_EQ(SSL_CTX_use_PrivateKey_file(
               server.ssl_ctx, "test/keys/key.pem", SSL_FILETYPE_PEM),
           1,
           "SSL_CTX_use_PrivateKey_file");

  /* Server part of the pair is uv_ssl_t */

  CHECK_NE(server.ssl = SSL_new(server.ssl_ctx), NULL, "SSL_new(server)");
  SSL_set_accept_state(server.ssl);

  CHECK_NE(server.ssl_link = uv_ssl_create(loop, server.ssl, &err), NULL,
           "uv_ssl_create(server.ssl)");

  /* Client part of the pair is using `SSL_set_fd()` */

  CHECK_NE(client.ssl = SSL_new(client.ssl_ctx), NULL, "SSL_new(client)");
  SSL_set_connect_state(client.ssl);
  SSL_set_fd(client.ssl, fds[0]);

  CHECK_EQ(uv_link_chain((uv_link_t*) &server.source,
                         (uv_link_t*) server.ssl_link),
           0,
           "uv_link_chain(server.source)");

  /* Create observer */
  CHECK_EQ(uv_link_observer_init(&server.observer), 0,
           "uv_link_observer_init(server.observer)");

  CHECK_EQ(uv_link_chain((uv_link_t*) server.ssl_link,
                         (uv_link_t*) &server.observer),
           0,
           "uv_link_chain(server.ssl_link)");

  /* Start client thread */

  CHECK_EQ(uv_thread_create(&client.thread, client_thread_body, client_fn), 0,
           "uv_thread_create(client.thread)");

  /* Pre-start server */
  CHECK_EQ(uv_link_read_start((uv_link_t*) &server.observer), 0,
           "uv_link_read_start()");

  server_fn();

  uv_thread_join(&client.thread);

  /* Free resources */

  if (!server.closed) {
    uv_link_close((uv_link_t*) &server.observer, common_close_cb);

    CHECK_EQ(uv_run(loop, UV_RUN_DEFAULT), 0, "uv_run() post");
    CHECK_EQ(close_cb_called, 1, "close_cb must be called");
  }

  SSL_free(server.ssl);
  SSL_free(client.ssl);
  SSL_CTX_free(server.ssl_ctx);
  SSL_CTX_free(client.ssl_ctx);

  memset(&server, 0, sizeof(server));
  memset(&client, 0, sizeof(client));

  CHECK_EQ(close(fds[0]), 0, "close(fds[0])");
  CHECK_NE(close(fds[1]), 0, "close(fds[1]) must fail");
}

#endif  /* TEST_SRC_TEST_COMMON_H_ */
