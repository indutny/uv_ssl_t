dist:
	./gyp_uv_ssl -Duv_dir=`pwd`/test/deps/libuv \
		-Duv_link_t_dir=`pwd`/test/deps/uv_link_t \
		-Dopenssl_dir=`pwd`/test/deps/bud/deps/openssl/openssl
	make -C out/ -j8

test:
	./gyp_uv_ssl test -Duv_dir=`pwd`/test/deps/libuv \
		-Duv_link_t_dir=`pwd`/test/deps/uv_link_t \
		-Dopenssl_dir=`pwd`/test/deps/bud/deps/openssl/openssl
	make -C out/ -j8
	./out/Release/uv_ssl_t-test

example:
	./gyp_uv_ssl example -Duv_dir=`pwd`/test/deps/libuv \
		-Duv_link_t_dir=`pwd`/test/deps/uv_link_t \
		-Dopenssl_dir=`pwd`/test/deps/bud/deps/openssl/openssl
	make -C out/ -j8
	./out/Release/uv_ssl_t-example

.PHONY: dist test example
