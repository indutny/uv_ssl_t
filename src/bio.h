#ifndef SRC_BIO_H_
#define SRC_BIO_H_

#include "openssl/bio.h"
#include "ringbuffer.h"

BIO* uv_ssl_bio_new(ringbuffer* buffer);
ringbuffer* uv_ssl_bio_get_buffer(BIO* bio);

#endif  /* SRC_BIO_H_ */
