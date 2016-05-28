#include "test-common.h"

static int read_cb_called;


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

  CHECK_EQ(uv_link_read_stop((uv_link_t*) &server.observer), 0,
           "uv_link_read_stop(server.observer)");
}


static void read_incoming_server() {
  server.observer.observer_read_cb = read_incoming_read_cb;

  read_cb_called = 0;
  CHECK_EQ(uv_run(loop, UV_RUN_DEFAULT), 0, "uv_run()");
  CHECK_EQ(read_cb_called, 1, "number of read_cb's");
}


TEST_IMPL(read_incoming) {
  ssl_client_server_test(read_incoming_client, read_incoming_server);
}
