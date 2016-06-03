#include "test-common.h"

static int read_cb_called;


static void cir_client() {
  CHECK_EQ(SSL_write(client.ssl, "hello", 5), 5, "SSL_write() == 5");
}


static void cir_close_cb(uv_link_t* link) {
  CHECK_EQ(link, (uv_link_t*) &server.observer, "close_cb link");
  close_cb_called++;
}


static void cir_read_cb(uv_link_observer_t* observer,
                        ssize_t nread,
                        const uv_buf_t* buf) {
  if (nread == 0)
    return;
  CHECK(nread > 0, "read error");

  read_cb_called++;

  server.closed = 1;
  uv_link_close((uv_link_t*) &server.observer, cir_close_cb);
}


static void cir_server() {
  server.observer.observer_read_cb = cir_read_cb;

  read_cb_called = 0;
  CHECK_EQ(uv_run(loop, UV_RUN_DEFAULT), 0, "uv_run()");
  CHECK_EQ(read_cb_called, 1, "number of read_cb's");
  CHECK_EQ(close_cb_called, 1, "number of close_cb's");
}


TEST_IMPL(close_in_read_cb) {
  ssl_client_server_test(cir_client, cir_server);
}
