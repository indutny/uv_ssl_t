test: dist
	./out/Release/uv_ssl_t-test

example: dist
	./out/Release/uv_ssl_t-example

dist:
	gypkg build uv_ssl_t.gyp

.PHONY: test example dist
