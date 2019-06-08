## hprox

[![CircleCI](https://circleci.com/gh/bjin/hprox.svg?style=shield)](https://circleci.com/gh/bjin/hprox)
[![Hackage](https://img.shields.io/hackage/v/hprox.svg)](https://hackage.haskell.org/package/hprox)
![Depends](https://img.shields.io/hackage-deps/v/hprox.svg)
[![License](https://img.shields.io/github/license/bjin/hprox.svg)](https://github.com/bjin/hprox/blob/master/LICENSE)

hprox is a lightweight HTTP/HTTPS proxy server.

### Features

* Basic HTTP proxy functionality, including `HTTP GET` and `HTTP CONNECT` support.
* Simple password authentication.
* HTTPS encryption (requires a valid certificate). Supports `TLS 1.3` and `HTTP 2`, also known as SPDY Proxy.
* TLS SNI validation for HTTPS connections, which blocks all incoming connections with wrong domain name.
* Provide PAC file for easy client side configuration. Supports Chrome and Firefox.
* Can run upon any Haskell Web Application with `wai` interface. Defaults to a dumb application which simulate the default empty page from Apache.
* Websocket redirection. Compatible with [v2ray-plugin for shadowsocks](https://github.com/shadowsocks/v2ray-plugin).
* Reverse proxy support, which redirect requests to a fallback server.

Use `hprox --help` to list the options for further details.

### Installation

Only Linux and macOS are supported. [stack](https://docs.haskellstack.org/en/stable/README/#how-to-install) is required to build `hprox`.

```sh
stack install
```

### Known Issue

* Only HTTP server are supported for websocket and reverse proxy redirection.
* Passwords are stored in plain text for now, please avoid using existing password.

### License

`hprox` is licensed under the Apache license. See LICENSE file for details.
