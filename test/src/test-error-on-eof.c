#include "test-common.h"

static int read_cb_called;


static void error_on_eof_client() {
  int err;

  do
    err = shutdown(fds[0], SHUT_RDWR);
  while (err == -1 && errno == EINTR);
}


static void error_on_eof_read_cb(uv_link_observer_t* observer,
                                 ssize_t nread,
                                 const uv_buf_t* buf) {
  if (nread == 0)
    return;

  CHECK_EQ(nread, UV_EPROTO, "observer_read_cb unexpectected error code");
  read_cb_called++;

  CHECK_EQ(uv_link_read_stop((uv_link_t*) &server.observer), 0,
           "uv_link_read_stop(server.observer)");
}


static void error_on_eof_server() {
  server.observer.observer_read_cb = error_on_eof_read_cb;

  read_cb_called = 0;
  CHECK_EQ(uv_run(loop, UV_RUN_DEFAULT), 0, "uv_run()");
  CHECK_EQ(read_cb_called, 1, "number of read_cb's");
}


TEST_IMPL(error_on_eof) {
  ssl_client_server_test(error_on_eof_client, error_on_eof_server);
}
