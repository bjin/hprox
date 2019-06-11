## hprox

[![CircleCI](https://circleci.com/gh/bjin/hprox.svg?style=shield)](https://circleci.com/gh/bjin/hprox)
[![Depends](https://img.shields.io/hackage-deps/v/hprox.svg)](https://packdeps.haskellers.com/feed?needle=hprox)
[![Release](https://img.shields.io/github/release/bjin/hprox.svg)](https://github.com/bjin/hprox/releases)
[![Hackage](https://img.shields.io/hackage/v/hprox.svg)](https://hackage.haskell.org/package/hprox)
[![License](https://img.shields.io/github/license/bjin/hprox.svg)](https://github.com/bjin/hprox/blob/master/LICENSE)

`hprox` is a lightweight HTTP/HTTPS proxy server.

### Features

* Basic HTTP proxy functionality.
* Simple password authentication.
* HTTPS encryption (requires a valid certificate). Supports TLS 1.3 and HTTP 2, also known as SPDY Proxy.
* TLS SNI validation (blocks all clients with invalid domain name).
* Provide PAC file for easy client side configuration (supports Chrome and Firefox).
* Websocket redirection (compatible with [v2ray-plugin for shadowsocks](https://github.com/shadowsocks/v2ray-plugin)).
* Reverse proxy support (redirect requests to a fallback server).
* Implemented as a middleware, compatible with any Haskell Web Application with `wai` interface.
  Defaults to fallback to a dumb application which simulate the default empty page from Apache.

Use `hprox --help` to list the options for further details.

### Installation

`hprox` should build and work on all unix-like OS with `ghc` support, but it's only
been tested on Linux and macOS.

[stack](https://docs.haskellstack.org/en/stable/README/#how-to-install) is required to build `hprox`.

```sh
stack install
```

### Known Issue

* Only HTTP servers are supported as websocket and reverse proxy redirection destination.
* Passwords are currently stored in plain text, please set permission accordingly and
  avoid using existing password.

### License

`hprox` is licensed under the Apache license. See LICENSE file for details.
