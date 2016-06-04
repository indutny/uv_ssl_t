#ifndef SRC_ERRORS_H_
#define SRC_ERRORS_H_

enum {
  kUVSSLErrUnexpectedEOF = UV_ERRNO_MAX - 1,
  kUVSSLErrCycleInput = UV_ERRNO_MAX - 2,
  kUVSSLErrSSLWrite = UV_ERRNO_MAX - 3,
  kUVSSLErrSSLSyncWrite = UV_ERRNO_MAX - 4
};

#endif  /* SRC_ERRORS_H_ */
