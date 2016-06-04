#include "test-common.h"

static int read_cb_called;


static void error_client() {
  int err;
  char buf[1024];

  memset(buf, 'x', sizeof(buf));

  do
    err = write(fds[0], buf, sizeof(buf));
  while (err == -1 && errno == EINTR);
}


static void error_read_cb(uv_link_observer_t* observer,
                          ssize_t nread,
                          const uv_buf_t* buf) {
  const char* msg;
  if (nread == 0)
    return;

  msg = uv_link_strerror((uv_link_t*) &server.observer, nread);
  CHECK_EQ(strcmp(msg, "uv_ssl_t: SSL_read() error"), 0,
           "observer_read_cb unexpectected error code");
  read_cb_called++;

  CHECK_EQ(uv_link_read_stop((uv_link_t*) &server.observer), 0,
           "uv_link_read_stop(server.observer)");
}


static void error_server() {
  server.observer.observer_read_cb = error_read_cb;

  read_cb_called = 0;
  CHECK_EQ(uv_run(loop, UV_RUN_DEFAULT), 0, "uv_run()");
  CHECK_EQ(read_cb_called, 1, "number of read_cb's");
}


TEST_IMPL(error_when_reading) {
  ssl_client_server_test(error_client, error_server);
}
