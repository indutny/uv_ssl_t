#ifndef INCLUDE_UV_SSL_H_
#define INCLUDE_UV_SSL_H_

#include "openssl/ssl.h"

#include "uv.h"
#include "uv_link_t.h"

typedef struct uv_ssl_s uv_ssl_t;

UV_EXTERN uv_ssl_t* uv_ssl_create(SSL* ssl, int* err);
UV_EXTERN void uv_ssl_destroy(uv_ssl_t* s);

UV_EXTERN uv_link_t* uv_ssl_get_link(uv_ssl_t* s);

#endif  /* INCLUDE_UV_LINK_H_ */
