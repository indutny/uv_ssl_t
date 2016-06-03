#ifndef INCLUDE_UV_SSL_H_
#define INCLUDE_UV_SSL_H_

#include "openssl/ssl.h"

#include "uv.h"
#include "uv_link_t.h"

/* NOTE: can be cast to `uv_link_t` */
typedef struct uv_ssl_s uv_ssl_t;

UV_EXTERN uv_ssl_t* uv_ssl_create(uv_loop_t* loop, SSL* ssl, int* err);

int uv_ssl_setup_recommended_secure_context(SSL_CTX* ctx);

#endif  /* INCLUDE_UV_LINK_H_ */
