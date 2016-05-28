#include "test-common.h"

static int handshakes_done;


static void handshake_client() {
  /* no-op */
}


static void handshake_info_cb(const SSL* ssl, int where, int val) {
  if ((where & SSL_CB_HANDSHAKE_DONE) != 0) {
    handshakes_done++;
    CHECK_EQ(uv_link_read_stop((uv_link_t*) &server.observer), 0,
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
