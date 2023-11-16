## 0.5.4

- routable `--rev` reverse proxy support
- fix `Keep-Alive` header in reverse HTTP/2 proxy
- add nix based build mode
- naiveproxy padding: add protocol negotiation and packet fragmentation 

## 0.5.3

- add macos-aarch64 build
- add `--hide` option for probe resistance
- gracefully close stream for HTTP CONNECT
- `gzip` encoding middleware removed

## 0.5.2

- add Windows build
- remove `--user` option

## 0.5.1

- export `LogLevel` type to make `Config` actually customizable
- add `--log` option to specify logging type

## 0.5.0

- initial HTTP/3 (QUIC) support
- add logging based on fast-logger
- some minor tweaks

## 0.4.0

- naiveproxy compatible [padding](https://github.com/klzgrad/naiveproxy/#padding-protocol-an-informal-specification) support (`--naive`)
- strong TLS settings as advised by [SSL Labs ssltest](https://www.ssllabs.com/ssltest)

## 0.3.0

- initial version with exposed library interface
