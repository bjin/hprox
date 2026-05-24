## Unreleased

### Added
- Added an Hspec-based `hprox-test` suite with characterization coverage for CLI/default parsing, pure helpers, auth-file loading and rewriting, middleware endpoints, reverse-proxy routing and rewrites, HTTP/CONNECT proxy decisions, TLS/SNI selection, Warp/runtime exception handling, runner selection, DoH behavior, and naiveproxy padding.
- Added internal domain/runtime seams for `Config`, auth loading, reverse routes, proxy runtime construction, TLS/SNI setup, Warp settings, runner selection, platform-specific Unix/QUIC startup, log output parsing, header policy, DoH requests, and runtime configuration.

### Changed
- Refactored `Network.HProx.run` into focused internal modules while preserving the public `Network.HProx` API and existing runtime behavior.
- Replaced tuple-heavy reverse-proxy internals with typed `ReverseRoute` and request rewrite helpers.
- Made proxy logging effects explicit by removing the hidden `unsafePerformIO` logging path.
- Centralized current header constants and strip/lookup policy, then made protocol header value comparisons case-insensitive for `X-Forwarded-Proto` and `X-Scheme`.
- Refactored DoH handling into explicit parse/resolve/respond helpers and made POST body reading support split request chunks within the existing 4096-byte limit.
- Named naiveproxy padding protocol constants and added deterministic parser/round-trip coverage.
- Updated copyright notices to 2026 in LICENSE, package metadata, and all touched source/test headers

### Fixed
- Removed avoidable partial functions in reverse-proxy host parsing and HTTP/WebSocket proxy target selection.
- Hardened malformed HTTP proxy target parsing to reject malformed explicit ports and HTTP/2 proxy requests without a Host header while preserving bracketed IPv6 authorities.
- Replaced the Argon2 password-hash `error` path with a typed `PasswordHashError` thrown at the IO boundary.
- Normalized HTTP proxy forwarding authority to render Host from the parsed URI and omit default `:80`
- Stripped inbound Host and proxy-boundary headers (including `Forwarded`) when forwarding proxied HTTP requests
## 0.6.5

- bump stack dependencies
- build with GHC 9.10
- remove DROP_ALL_CAPS_EXCEPT_BIND

## 0.6.4

- bump stack dependencies
- build with GHC 9.8

## 0.6.3

- bump stack dependencies
- fix Content-Length header for encoded HTTP responses in reverse proxy mode

## 0.6.2

- fixes to improve ssltest result
- unix: support setuid after binding port
- remove graceful close

## 0.6.1

- multiple certificates and SNI support for HTTP/3
- install signal handler with graceful shutdown on Linux and macOS
- support ACME `http-01` challenge (RFC8555)

## 0.6.0

- `--rev` now supports domain matching
- fix `Content-Length` header in HTTP/2 responses
- passwords are now Argon2 salt-hashed

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
