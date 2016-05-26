{
  "targets": [{
    "target_name": "uv_ssl_t",
    "type": "<(library)",

    "direct_dependent_settings": {
      "include_dirs": [ "include" ],
    },
    "include_dirs": [
      # libuv
      "<(uv_dir)/include",

      # uv_link_t
      "<(uv_link_t_dir)/include",

      # openssl
      "<(openssl_dir)/include",

      ".",
    ],

    "dependencies": [
      "deps/ringbuffer/ringbuffer.gyp:ringbuffer",
    ],

    "sources": [
      "src/bio.c",
      "src/link_methods.c",
      "src/uv_ssl_t.c",
    ],
  }],
}
