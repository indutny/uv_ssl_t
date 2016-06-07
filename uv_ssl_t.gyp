{
  "targets": [{
    "target_name": "uv_ssl_t",
    "type": "<!(gypkg type)",

    "variables": {
      "gypkg_deps": [
        "git://github.com/libuv/libuv.git@^1.9.0:uv.gyp:libuv",
        "git://github.com/indutny/uv_link_t@^1.0.0:uv_link_t.gyp:uv_link_t",
        "git://github.com/indutny/bud@^4.0.3:deps/openssl/openssl.gyp:openssl",
      ],
    },

    "dependencies": [
      "<!@(gypkg deps <(gypkg_deps))",
      "deps/ringbuffer/ringbuffer.gyp:ringbuffer",
    ],

    "direct_dependent_settings": {
      "include_dirs": [ "include" ],
    },

    "include_dirs": [
      ".",
    ],

    "sources": [
      "src/bio.c",
      "src/link_methods.c",
      "src/uv_ssl_t.c",
    ],
  }],
}
