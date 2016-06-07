test: dist
	./out/Release/uv_ssl_t-test

example: dist
	./out/Release/uv_ssl_t-example

dist:
	gypkg gen uv_ssl_t.gyp
	make -C out/ -j8

.PHONY: test example dist
