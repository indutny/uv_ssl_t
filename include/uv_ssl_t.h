#ifndef INCLUDE_UV_SSL_H_
#define INCLUDE_UV_SSL_H_

/* NOTE: uv.h included first, because it sets up proper includes on Windows */
#include "uv.h"
#include "uv_link_t.h"

#include "openssl/ssl.h"

/* NOTE: can be cast to `uv_link_t` */
typedef struct uv_ssl_s uv_ssl_t;

UV_EXTERN uv_ssl_t* uv_ssl_create(uv_loop_t* loop, SSL* ssl, int* err);

int uv_ssl_setup_recommended_secure_context(SSL_CTX* ctx);

#endif  /* INCLUDE_UV_LINK_H_ */
