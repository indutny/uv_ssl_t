# uv_ssl_t
[![Build Status](https://secure.travis-ci.org/indutny/uv_ssl_t.png)](http://travis-ci.org/indutny/uv_ssl_t)

**HIGHLY UNSTABLE**

Chainable SSL implementation for [libuv][0] based on [uv_link_t][1].

## Why?

Doing SSL asynchronously is hard. This project provides abstract interface that
works well with the event loop model of [libuv][0].

## How?

The decoupled interface backend is provided by [uv_link_t][1], and is used
extensively in this project.

Example is available [here][2].

## LICENSE

This software is licensed under the MIT License.

Copyright Fedor Indutny, 2016.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.

[0]: https://github.com/libuv/libuv
[1]: https://github.com/indutny/uv_link_t
[2]: https://github.com/indutny/uv_ssl_t/tree/master/example
