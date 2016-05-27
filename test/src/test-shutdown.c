#include "test-common.h"

static int shutdown_called;
static int handshakes_done;
static int test_arg;

static void shutdown_client() {
  char buf[1024];

  CHECK_EQ(SSL_read(client.ssl, buf, sizeof(buf)), 0, "SSL_read() == 0");
  CHECK_EQ(SSL_get_shutdown(client.ssl), SSL_RECEIVED_SHUTDOWN,
           "SSL_get_shutdown() == SSL_RECEIVED_SHUTDOWN");
}


static void shutdown_cb(uv_link_t* link, int status, void* arg) {
  CHECK_EQ(link, &server.observer.link, "shutdown_cb link");
  CHECK_EQ(arg, &test_arg, "shutdown_cb arg");

  shutdown_called++;
}


static void write_info_cb(const SSL* ssl, int where, int val) {
  if ((where & SSL_CB_HANDSHAKE_DONE) != 0) {
    CHECK_EQ(uv_link_read_stop(&server.observer.link), 0,
             "uv_link_read_stop(server)");
    handshakes_done++;
  }
}


static void shutdown_server() {
  uv_link_t* serv;

  serv = &server.observer.link;
  SSL_set_info_callback(server.ssl, write_info_cb);

  CHECK_EQ(uv_run(loop, UV_RUN_DEFAULT), 0, "uv_run()");
  CHECK_EQ(handshakes_done, 1, "handshake happened");

  /* NOTE: uv_run() will exit after handshake */
  CHECK_EQ(uv_run(loop, UV_RUN_DEFAULT), 0, "uv_run()");

  uv_link_shutdown(serv, serv, shutdown_cb, &test_arg);

  CHECK_EQ(uv_run(loop, UV_RUN_DEFAULT), 0, "uv_run()");
}


TEST_IMPL(shutdown) {
  ssl_client_server_test(shutdown_client, shutdown_server);
}
