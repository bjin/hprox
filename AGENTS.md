# hprox Agent Guide

Use this as the fast path for future work in this repository. The codebase now has characterization tests; do not treat builds alone as enough for non-trivial changes.

## Commands

### Core verification

```bash
stack test
stack build --pedantic
```

### Build targets

```bash
stack build hprox:lib
stack build hprox:exe:hprox
stack build --flag hprox:quic hprox:exe:hprox
stack build --flag hprox:-quic hprox:exe:hprox
```

### Executable smoke checks

```bash
stack exec hprox -- --help
stack exec hprox -- --version
```

### Formatting

Run `stylish-haskell -i` on the Haskell files you changed. Do not reformat unrelated files.

```bash
stylish-haskell -i src/Network/HProx.hs test/Network/HProx/RuntimeSpec.hs
```

## When to run what

- Haskell code change: `stylish-haskell -i <changed .hs files>`, `stack test`, `stack build --pedantic`.
- Public API, package wiring, executable startup, runtime orchestration: also run `stack build hprox:lib`, `stack build hprox:exe:hprox`, and `stack exec hprox -- --help`.
- CPP-sensitive code or tests (`QUIC_ENABLED`, `OS_UNIX`, platform modules, config fields): also run both QUIC and no-QUIC builds/tests where relevant.
- Test/package configuration changes: also run `stack test --pedantic` if the change affects test setup or warning behavior.
- Documentation-only changes: no build required; state that no tests were run.

## Current architecture

Public facade:

- `Network.HProx` exports the public API: `Config(..)`, `CertFile(..)`, `LogLevel(..)`, `defaultConfig`, `getConfig`, `run`.
- Keep this API stable unless the user explicitly asks for a breaking change.

Internal modules:

- `Network.HProx.Config`: CLI parser, public `Config`, defaults.
- `Network.HProx.Auth`: auth-file loading, hashing, rewrite, verifier construction.
- `Network.HProx.Route`: typed reverse routes and reverse-proxy rewrite helpers.
- `Network.HProx.Headers`: shared header names, strip policy, protocol value comparison.
- `Network.HProx.Impl`: WAI middleware and HTTP/CONNECT proxy behavior.
- `Network.HProx.Runtime`: runtime config normalization, proxy runtime construction, TLS/SNI, Warp settings, runner selection, exception/access logging.
- `Network.HProx.Platform.Unix`: privilege dropping.
- `Network.HProx.Platform.Quic`: QUIC + TLS runner wiring.
- `Network.HProx.DoH`: DNS-over-HTTPS parsing/resolution/response helpers.
- `Network.HProx.Naive`: naiveproxy padding negotiation and conduit transforms.
- `Network.HProx.Log`: log levels, typed log output parsing, fast-logger integration.
- `Network.HProx.Util`: small parsing/password/response helpers.

## Tests

Tests live under `test/Network/HProx/*Spec.hs` and are wired through `test/Spec.hs`. They intentionally include white-box tests against `src` modules; do not expose internals from the library just for tests.

Existing coverage includes:

- CLI/default config parsing.
- Pure parsing/password/log helpers.
- Auth-file IO behavior.
- Middleware endpoints.
- Reverse-route matching and rewriting.
- HTTP/CONNECT proxy auth and target selection.
- TLS/SNI selection.
- Warp/runtime settings, runner selection, exception filtering.
- DoH GET/POST behavior and split POST bodies.
- Naiveproxy padding negotiation and conduit round trips.

When changing behavior, add or update the focused spec first. Prefer testing the small seam that owns the decision rather than a broad network integration.

## Coding rules that matter

- Preserve behavior unless the requested change is explicitly a behavior change.
- Prefer small domain types and named helpers over tuple-heavy or guard-heavy logic.
- Avoid partial functions (`fromJust`, `head`, `error`) in production paths. Make invariants explicit with pattern matching or typed failures.
- Keep effects visible. Do not hide IO behind pure APIs.
- Use records for multi-field data and construction sites where field order could become fragile.
- Keep public `Config(..)` shape stable unless explicitly asked otherwise.
- Use `ByteString` for request/header/proxy data already represented as bytes; avoid unnecessary `String`/`Text` conversions.
- Use `Maybe`/`Either` for expected parse failures. Throw typed exceptions only at IO boundaries.
- Keep CPP at module boundaries when practical.
- Add new internal modules to `package.yaml` under `library.other-modules`.

## Style

- Follow `HASKELL-STYLE.md` for Haskell source style in `src/` and `app/`.
- Let `stylish-haskell` decide import layout and alignment, then review formatter output for CPP-sensitive code.
- Use explicit export lists for every module.
- Add top-level type signatures.
- Qualified imports are preferred when they improve clarity, especially for `ByteString`, `Text`, DNS, TLS, and HTTP modules.
- Comments should explain protocol constraints or non-obvious behavior preservation, not restate the code.

## CI

CI builds release artifacts and now runs tests after build/install:

- CircleCI: Linux x86_64, Linux aarch64, Windows.
- GitHub Actions: macOS aarch64.

Keep CI commands aligned with local Stack flags when changing package flags, resolver, or test setup.

## Commit hygiene

- Stage only intended files.
- Keep commits focused.
- Prefer `omp commit -c "<CONTEXT>"` when `omp` is available. Use direct `git commit` only when the user explicitly asks for it.
- For behavior-preserving refactors, mention the tests/builds run and the behavior boundary preserved.
- For documentation-only commits, state that no tests were run.
