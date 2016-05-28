#ifndef TEST_SRC_TEST_LIST_H_
#define TEST_SRC_TEST_LIST_H_

#define TEST_ENUM(V)                                                          \
    V(handshake)                                                              \
    V(read_incoming)                                                          \
    V(write)                                                                  \
    V(try_write)                                                              \
    V(shutdown)                                                               \
    V(error_when_reading)                                                     \
    V(error_on_eof)                                                           \

#define TEST_DECL(N) void test__##N();

TEST_ENUM(TEST_DECL)

#undef TEST_DECL

#define TEST_FN(N) test__##N
#define TEST_IMPL(N) void test__##N()

#endif  /* TEST_SRC_TEST_LIST_H_ */
