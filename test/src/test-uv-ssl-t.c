#include <sys/socket.h>
#include <unistd.h>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

#include "test-common.h"

static int fds[2];
static uv_loop_t* loop;
static uv_pipe_t pair_right;
static uv_link_source_t source;
static uv_link_observer_t observer;
static uv_ssl_t* ssl_link;
static SSL_CTX* ssl_ctx_left;
static SSL* ssl_left;
static SSL_CTX* ssl_ctx_right;
static SSL* ssl_right;
static uv_thread_t client_thread;


static int handshakes_done;
static int read_cb_called;


static void client_thread_body(void* arg) {
  int err;

  err = SSL_connect(ssl_left);
  if (err != 1)
    goto fail;

  CHECK_EQ(SSL_write(ssl_left, "hello", 5), 5, "SSL_write() == 5");

  return;

fail:
  ERR_print_errors_fp(stderr);
  CHECK(0, "SSL_connect() != 0");
}


static void ssl_right_info_cb(const SSL* ssl, int where, int val) {
  if ((where & SSL_CB_HANDSHAKE_DONE) != 0)
    handshakes_done++;
}


static void observer_read_cb(uv_link_observer_t* observer,
                             ssize_t nread,
                             const uv_buf_t* buf) {
  if (nread == 0)
    return;

  CHECK_EQ(nread, 5, "observer_read_cb data size match");
  CHECK_EQ(strcmp(buf->base, "hello"), 0, "observer_read_cb data match");

  read_cb_called++;

  CHECK_EQ(uv_link_read_stop(&observer->link), 0, "uv_link_read_stop()");
}


TEST_IMPL(uv_ssl_t) {
  int err;

  loop = uv_default_loop();
  CHECK_NE(loop, NULL, "uv_default_loop()");

  CHECK_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0, "socketpair()");

  /* Initialize source */

  CHECK_EQ(uv_pipe_init(loop, &pair_right, 0), 0, "uv_pipe_init(pair_right)");
  CHECK_EQ(uv_pipe_open(&pair_right, fds[1]), 0, "uv_pipe_open(pair_right)");

  CHECK_EQ(uv_link_source_init(&source, (uv_stream_t*) &pair_right), 0,
           "uv_link_source_init()");

  /* Initialize SSL_CTX */

  ssl_ctx_left = SSL_CTX_new(TLSv1_2_method());
  CHECK_NE(ssl_ctx_left, NULL, "SSL_CTX_new");
  ssl_ctx_right = SSL_CTX_new(TLSv1_2_method());
  CHECK_NE(ssl_ctx_right, NULL, "SSL_CTX_new");

  CHECK_EQ(SSL_CTX_use_certificate_file(
               ssl_ctx_right, "test/keys/cert.pem", SSL_FILETYPE_PEM),
           1,
           "SSL_CTX_use_certificate_file");
  CHECK_EQ(SSL_CTX_use_PrivateKey_file(
               ssl_ctx_right, "test/keys/key.pem", SSL_FILETYPE_PEM),
           1,
           "SSL_CTX_use_PrivateKey_file");

  /* Right part of the pair is uv_ssl_t */

  ssl_right = SSL_new(ssl_ctx_right);
  CHECK_NE(ssl_right, NULL, "SSL_new(left)");
  SSL_set_accept_state(ssl_right);

  ssl_link = uv_ssl_create(ssl_right, &err);
  CHECK_NE(ssl_link, NULL, "uv_ssl_create");

  /* Left part of the pair is using `SSL_set_fd()` */

  ssl_left = SSL_new(ssl_ctx_left);
  CHECK_NE(ssl_left, NULL, "SSL_new(left)");
  SSL_set_connect_state(ssl_left);
  SSL_set_fd(ssl_left, fds[0]);

  CHECK_EQ(uv_link_chain(&source.link, uv_ssl_get_link(ssl_link)), 0,
           "uv_link_chain()");

  /* Create observer */
  CHECK_EQ(uv_link_observer_init(&observer, uv_ssl_get_link(ssl_link)), 0,
           "uv_link_observer_init()");

  CHECK_EQ(uv_link_read_start(&observer.link), 0, "uv_link_read_start()");
  observer.read_cb = observer_read_cb;
  SSL_set_info_callback(ssl_right, ssl_right_info_cb);

  /* Start client thread */

  CHECK_EQ(uv_thread_create(&client_thread, client_thread_body, NULL), 0,
           "uv_thread_create()");

  uv_run(loop, UV_RUN_DEFAULT);

  uv_thread_join(&client_thread);

  CHECK_EQ(handshakes_done, 1, "number of handshakes");
  CHECK_EQ(read_cb_called, 1, "number of reads");

  /* Free resources */

  CHECK_EQ(uv_link_observer_close(&observer), 0, "uv_link_observer_close()");
  uv_ssl_destroy(ssl_link);
  uv_link_source_close(&source);
  uv_close((uv_handle_t*) &pair_right, NULL);

  SSL_free(ssl_left);
  SSL_free(ssl_right);
  SSL_CTX_free(ssl_ctx_left);
  SSL_CTX_free(ssl_ctx_right);

  CHECK_EQ(close(fds[0]), 0, "close(fds[0])");
}
