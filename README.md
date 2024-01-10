## hprox

[![CircleCI](https://circleci.com/gh/bjin/hprox.svg?style=shield)](https://circleci.com/gh/bjin/hprox)
[![CirrusCI](https://api.cirrus-ci.com/github/bjin/hprox.svg)](https://cirrus-ci.com/github/bjin/hprox)
[![Depends](https://img.shields.io/hackage-deps/v/hprox.svg)](https://packdeps.haskellers.com/feed?needle=hprox)
[![Release](https://img.shields.io/github/release/bjin/hprox.svg)](https://github.com/bjin/hprox/releases)
[![Hackage](https://img.shields.io/hackage/v/hprox.svg)](https://hackage.haskell.org/package/hprox)
[![License](https://img.shields.io/github/license/bjin/hprox.svg)](https://github.com/bjin/hprox/blob/master/LICENSE)

`hprox` is a lightweight HTTP/HTTPS proxy server.

### Features

* Basic HTTP proxy functionality.
* [Basic](https://en.wikipedia.org/wiki/Basic_access_authentication) password authentication.
* Enables TLS encryption, requiring a valid certificate. Supports TLS 1.3 and HTTP/2, also known as SPDY Proxy.
* TLS SNI validation (blocks all clients with an invalid domain name).
* Provides a PAC file for seamless client-side configuration, compatible with browsers like Chrome and Firefox.
* Websocket redirection (compatible with [v2ray-plugin](https://github.com/shadowsocks/v2ray-plugin)).
* Reverse proxy support (redirects requests to a fallback server).
* DNS-over-HTTPS (DoH) support.
* [naiveproxy](https://github.com/klzgrad/naiveproxy) compatible [padding](https://github.com/klzgrad/naiveproxy/#padding-protocol-an-informal-specification) (HTTP Connect proxy).
* HTTP/3 (QUIC) support (`h3` protocol).
* ACME `http-01` challenge as specified by RFC8555, see [acme.sh stateless mode](https://github.com/acmesh-official/acme.sh/wiki/Stateless-Mode).
* Designed as a middleware, ensuring compatibility with any Haskell Web Application built using the `wai` interface.
  Refer to [library documents](https://hackage.haskell.org/package/hprox) for details.

### Installation

`hprox` is designed to build and function seamlessly on all Unix-like operating systems with GHC support, as well as on Windows environments.

[stack](https://docs.haskellstack.org/en/stable/README/#how-to-install) is recommended for building `hprox`.

```sh
stack setup
stack install
```

Alternatively, you have the option to utilize the statically linked binary available in the [latest release](https://github.com/bjin/hprox/releases).

### Usage

Utilize `hprox --help` to view a comprehensive list of options along with detailed explanations.

* To run `hprox` on port 8080 with simple password authentication (passwords will be [Argon2-hashed](https://en.wikipedia.org/wiki/Argon2) after first run):

```sh
echo "user:pass" > userpass.txt
hprox -p 8080 -a userpass.txt
```

* To run `hprox` with TLS encryption on port 443, with a certificate for `example.com` obtained with [acme.sh](https://acme.sh/):

```sh
hprox -p 443 -s example.com:$HOME/.acme.sh/example.com/fullchain.cer:$HOME/.acme.sh/example.com/example.com.key
```

Browsers can be configured with the PAC file URL `https://example.com/.hprox/config.pac`.

* For integration with `v2ray-plugin` and a fallback page to the [Ubuntu archive](http://archive.ubuntu.com/):

```sh
v2ray-plugin -server -localPort 8080 -mode websocket -host example.com -remotePort xxxx
hprox -p 443 -s example.com:fullchain.pem:privkey.pem --ws 127.0.0.1:8080 --rev archive.ubuntu.com:80
```

Clients can establish connections using the plugin option `tls;host=example.com`.

* Enable HTTP/3 (QUIC) on UDP port 8443, enable DoH support (redirect to 8.8.8.8), and add naiveproxy compatible padding:

```sh
hprox -p 443 -q 8443 -s example.com:fullchain.pem:privkey.pem -a userpass.txt --naive --doh 8.8.8.8
```

Then DoH can be accessed at `https://example.com/dns-query`.

### License

`hprox` is licensed under the Apache license. Refer to the `LICENSE` file for comprehensive details.
