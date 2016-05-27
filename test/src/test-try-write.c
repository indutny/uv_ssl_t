#include "test-common.h"

static int handshakes_done;

static void write_client() {
  char buf[1024];

  CHECK_EQ(SSL_read(client.ssl, buf, sizeof(buf)), 5, "SSL_read() == 5");
  CHECK_EQ(strncmp(buf, "hello", 5), 0, "write_client data match");
}


static void write_info_cb(const SSL* ssl, int where, int val) {
  if ((where & SSL_CB_HANDSHAKE_DONE) != 0) {
    CHECK_EQ(uv_link_read_stop(&server.observer.link), 0,
             "uv_link_read_stop(server)");
    handshakes_done++;
  }
}


static void write_server() {
  uv_buf_t buf;
  uv_link_t* serv;

  serv = &server.observer.link;
  SSL_set_info_callback(server.ssl, write_info_cb);

  CHECK_EQ(uv_run(loop, UV_RUN_DEFAULT), 0, "uv_run()");
  CHECK_EQ(handshakes_done, 1, "handshake happened");

  /* NOTE: uv_run() will exit after handshake */

  buf = uv_buf_init("hello", 5);
  CHECK_EQ(uv_link_try_write(serv, &buf, 1), 5, "uv_link_try_write(server)");

  CHECK_EQ(uv_run(loop, UV_RUN_DEFAULT), 0, "uv_run()");
}


TEST_IMPL(try_write) {
  ssl_client_server_test(write_client, write_server);
}
