#include <sys/socket.h>
#include <unistd.h>

#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

#include "test-common.h"

static int read_cb_called;
static int handshakes_done;


static void handshake_read_cb(uv_link_observer_t* observer,
                              ssize_t nread,
                              const uv_buf_t* buf) {
  if (nread == 0)
    return;

  CHECK_EQ(nread, 5, "observer_read_cb data size match");
  CHECK_EQ(strncmp(buf->base, "hello", nread), 0,
           "observer_read_cb data match");

  read_cb_called++;

  CHECK_EQ(uv_link_read_stop(&observer->link), 0, "uv_link_read_stop()");
}


static void handshake_client() {
  /* no-op */
}


static void handshake_info_cb(const SSL* ssl, int where, int val) {
  if ((where & SSL_CB_HANDSHAKE_DONE) != 0) {
    handshakes_done++;
    CHECK_EQ(uv_link_read_stop(&server.observer.link), 0,
             "uv_link_read_stop()");
  }
}


static void handshake_server() {
  SSL_set_info_callback(server.ssl, handshake_info_cb);

  handshakes_done = 0;
  CHECK_EQ(uv_run(loop, UV_RUN_DEFAULT), 0, "uv_run()");
  CHECK_EQ(handshakes_done, 1, "number of handshakes");
}


TEST_IMPL(handshake) {
  ssl_client_server_test(handshake_client, handshake_server);
}


static void read_incoming_client() {
  CHECK_EQ(SSL_write(client.ssl, "hello", 5), 5, "SSL_write() == 5");
}


static void read_incoming_read_cb(uv_link_observer_t* observer,
                                  ssize_t nread,
                                  const uv_buf_t* buf) {
  if (nread == 0)
    return;

  CHECK_EQ(nread, 5, "observer_read_cb data size match");
  CHECK_EQ(strncmp(buf->base, "hello", nread), 0,
           "observer_read_cb data match");

  read_cb_called++;

  CHECK_EQ(uv_link_read_stop(&server.observer.link), 0,
           "uv_link_read_stop(server.observer.link)");
}


static void read_incoming_server() {
  server.observer.read_cb = read_incoming_read_cb;

  read_cb_called = 0;
  CHECK_EQ(uv_run(loop, UV_RUN_DEFAULT), 0, "uv_run()");
  CHECK_EQ(read_cb_called, 1, "number of read_cb's");
}


TEST_IMPL(read_incoming) {
  ssl_client_server_test(read_incoming_client, read_incoming_server);
}
