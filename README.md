# cookieauth

Cookie-based Basic-Authentication HTTP middleware for Go (golang). Prevents the need to keep entering basic-auth username and passwords over and over.

[![GoDoc](https://godoc.org/github.com/jpillora/cookieauth?status.svg)](https://godoc.org/github.com/jpillora/cookieauth)

### Usage

Get package:

``` sh
$ go get -v github.com/jpillora/cookieauth
```

Protect `handler` with a username and password:

``` go
handler := http.HandlerFunc(...)
protected := cookieauth.Wrap(handler, "myuser", "mypassword")
http.ListenAndServe(":3000", protected)
```

Successful logins are hashed and stored in the client's user agent.

#### MIT License

Copyright © 2016 Jaime Pillora &lt;dev@jpillora.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
