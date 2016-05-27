{
  "variables": {
  },
  "targets": [{
    "target_name": "uv_ssl_t-test",
    "type": "executable",

    "include_dirs": [
      "src"
    ],

    "dependencies": [
      "deps/libuv/uv.gyp:libuv",
      "deps/uv_link_t/uv_link_t.gyp:uv_link_t",
      "deps/bud/deps/openssl/openssl.gyp:openssl",
      "../uv_ssl_t.gyp:uv_ssl_t",
    ],

    "sources": [
      "src/main.c",
      "src/test-handshake.c",
      "src/test-read-incoming.c",
      "src/test-shutdown.c",
      "src/test-try-write.c",
      "src/test-write.c",
    ],
  }],
}
