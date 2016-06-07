{
  "targets": [{
    "target_name": "uv_ssl_t-test",
    "type": "executable",

    "include_dirs": [
      "src"
    ],

    "variables": {
      "gypkg_deps": [
        "git://github.com/libuv/libuv.git@^1.9.0 => uv.gyp:libuv",
        "git://github.com/indutny/uv_link_t@^1.0.0 => uv_link_t.gyp:uv_link_t",
        "git://github.com/indutny/bud@^4.0.3 => deps/openssl/openssl.gyp:openssl",
      ],
    },

    "dependencies": [
      "<!@(gypkg deps <(gypkg_deps))",
      "../uv_ssl_t.gyp:uv_ssl_t",
    ],

    "sources": [
      "src/main.c",
      "src/test-handshake.c",
      "src/test-error.c",
      "src/test-error-on-eof.c",
      "src/test-read-incoming.c",
      "src/test-shutdown.c",
      "src/test-try-write.c",
      "src/test-write.c",
      "src/test-close-in-read-cb.c",
    ],
  }],
}
