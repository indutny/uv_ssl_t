{
  "targets": [{
    "target_name": "uv_ssl_t-example",
    "type": "executable",

    "include_dirs": [
      "src"
    ],

    "dependencies": [
      "../test/deps/libuv/uv.gyp:libuv",
      "../test/deps/uv_link_t/uv_link_t.gyp:uv_link_t",
      "../test/deps/bud/deps/openssl/openssl.gyp:openssl",
      "../uv_ssl_t.gyp:uv_ssl_t",
    ],

    "sources": [
      "src/main.c",
      "src/middle.c",
    ],
  }],
}
