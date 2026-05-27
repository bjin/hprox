## Unreleased

### Added
- Added SIGHUP-triggered TLS credential reloading with fingerprint-based change detection
- Added runtime-driven SNI certificate lookup backed by a mutable TLS credential store

### Changed
- Refactored Warp and QUIC to consume dynamic credentials from the runtime store instead of static defaults
- Upgraded stack dependency snapshots and pinned TLS/QUIC-related packages to newer versions

### Fixed
- Stopped QUIC from keeping stale embedded credentials by using callback-based SNI resolution at handshake time

## 0.7.0

### Added
- Added an Hspec-based `hprox-test` suite with characterization coverage for CLI/default parsing, pure helpers, auth-file loading and rewriting, middleware endpoints, reverse-proxy routing and rewrites, HTTP/CONNECT proxy decisions, TLS/SNI selection, Warp/runtime exception handling, runner selection, DoH behavior, and naiveproxy padding.
- Added internal domain/runtime seams for `Config`, auth loading, reverse routes, proxy runtime construction, TLS/SNI setup, Warp settings, runner selection, platform-specific Unix/QUIC startup, log output parsing, header policy, DoH requests, and runtime configuration.
- Added runtime-spec coverage for safer QUIC defaults, including 0-RTT disablement, dual-stack wildcard binds, and Alt-Svc rendering assertions
- Added pure `planPrivilegeDrop` coverage for Unix privilege-drop plans in `RuntimeSpec`

### Changed
- Refactored `Network.HProx.run` into focused internal modules while preserving the public `Network.HProx` API and existing runtime behavior.
- Replaced tuple-heavy reverse-proxy internals with typed `ReverseRoute` and request rewrite helpers.
- Made proxy logging effects explicit by removing the hidden `unsafePerformIO` logging path.
- Centralized current header constants and strip/lookup policy, then made protocol header value comparisons case-insensitive for `X-Forwarded-Proto` and `X-Scheme`.
- Refactored DoH handling into explicit parse/resolve/respond helpers and made POST body reading support split request chunks within the existing 4096-byte limit.
- Named naiveproxy padding protocol constants and added deterministic parser/round-trip coverage.
- Updated copyright notices to 2026 in LICENSE, package metadata, and all touched source/test headers
- Hardened auth-file handling by stripping one trailing carriage return from each entry before parsing, hashing, and rewrite decisions
- Normalized reverse route host/path matching behavior is now stricter and more tolerant of case in host names
- Disabled QUIC 0-RTT startup by default and exposed configurable QUIC helper seams for safer runtime behavior tests
- Changed default QUIC bind behavior to listen on both 0.0.0.0 and :: when no explicit bind is provided, while singleton binds remain single-address
- Updated QUIC bind logging to report all interfaces when the bind address is not configured explicitly

### Fixed
- Removed avoidable partial functions in reverse-proxy host parsing and HTTP/WebSocket proxy target selection.
- Hardened malformed HTTP proxy target parsing to reject malformed explicit ports and HTTP/2 proxy requests without a Host header while preserving bracketed IPv6 authorities.
- Replaced the Argon2 password-hash `error` path with a typed `PasswordHashError` thrown at the IO boundary.
- Normalized HTTP proxy forwarding authority to render Host from the parsed URI and omit default `:80`
- Stripped inbound Host and proxy-boundary headers (including `Forwarded`) when forwarding proxied HTTP requests
- Enforced strict `Proxy-Authorization` parsing for HTTP proxy authentication: only `Basic` credentials with valid base64 decode are accepted now
- Ensured malformed auth-file warnings redact raw line contents and report line numbers with optional username context
- Added tests covering CRLF plaintext auth-file verification/rewrite and malformed-line log redaction
- Added bounded validation for `--port` and `--quic`, including `Config` runtime validation for direct values, and tightened `--rev` route parsing to reject empty upstream/domain components before startup
- Normalized reverse-route prefixes from config tuples to canonical leading-slash form without trailing slash
- Made reverse route prefix matching boundary-aware so /api matches /api/v1 but not /apiary or /apix
- Made reverse proxy path rewrites preserve unmatched paths and handle exact and nested matches consistently
- Compared reverse-route hostnames case-insensitively after stripping ports
- Preserved `forceSSL` HTTPS redirect targets for origin-form requests by keeping request path and query; for absolute-form proxy requests the redirect now uses the parsed target and omits default `:80`/`:443` ports while preserving non-default ports
- Updated CONNECT handling to establish upstream TCP before returning 200 OK and return 502 on connect failures for HTTP/1 and HTTP/2
- Differentiated DNS resolver failures in DoH by returning HTTP 502 (Bad Gateway) with `dns resolver failure` instead of reusing the malformed-request 400 response
- Rejected chunked DoH POST bodies that exceed the 4096-byte limit with HTTP 400 malformed-request handling
- Preserved malformed client input handling on HTTP 400 while adding successful chunked POST parsing support within existing size bounds
- Preserved Alt-Svc advertisement formatting by centralizing it in a dedicated helper used by TLS setup
- Hardened Unix privilege dropping to resolve target user/group entries before changing IDs
- Hardened TLS credential loading by adding contextual IO failures for missing or unreadable cert/key paths

### Security
- Redacted proxy credentials in TRACE logs as `username:<redacted>` so passwords are never logged
- Prevented auth-file logging from leaking password-like fragments by replacing raw-line diagnostics with non-sensitive context
- Hardened SNI matching to use ASCII case-insensitive host checks and reject invalid wildcard matches
- Disabled QUIC 0-RTT by default to reduce replay and forward-secrecy risk when accepting early data
- Verified real/effective UID/GID and supplementary groups after privilege drop and enforced stricter safety checks for user/group transitions

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
