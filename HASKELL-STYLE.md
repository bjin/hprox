# Haskell Source Style

This guide applies to Haskell source files under `src/` and `app/`. It does not apply to
`test/`, which may use test-local patterns when they make specifications clearer.

## Formatter

Run `stylish-haskell` on every changed Haskell source file:

```bash
stylish-haskell -i src/Network/HProx.hs app/Main.hs
```

The formatter is the baseline, not a substitute for review. In particular, review formatter
output around CPP-guarded exports/imports and keep the conditional structure intact.

The checked-in `.stylish-haskell.yaml` is authoritative. Its important settings are:

- `columns: 100`, `newline: lf`, trailing whitespace removed.
- Module headers use 2-space export indentation, open the export list on the next line, sort
  exports, and break at `where`.
- Imports are grouped/aligned by package group, post-qualified, padded by module name, and do not
  add spaces inside import lists.
- `simple_align` is enabled for cases, top-level patterns, records, and multi-way `if`.
- Language pragmas are vertical, aligned, and redundant pragmas are removed.

## File shape

Each source file follows this order:

1. SPDX and copyright comments.
2. Language pragmas, one per line.
3. Module declaration with an explicit export list.
4. Imports.
5. Types and functions.

```hs
-- SPDX-License-Identifier: Apache-2.0
--
-- Copyright (C) 2026 Bin Jin. All Rights Reserved.
{-# LANGUAGE CPP #-}

module Network.HProx
  ( CertFile(..)
  , Config(..)
  , run
  ) where
```

Export public modules, types, constructors, and functions intentionally. Do not expose internals
only to make tests easier.

## Imports

- External/package imports come first.
- Local `Network.HProx.*` imports come last, separated by a blank line.
- External imports may be split into small subgroups when that is already the local module pattern
  (for example, platform-only CPP imports after common imports).
- Prefer explicit imports for small import lists.
- Prefer qualified imports for frequently used namespaces such as `ByteString`, `Text`, DNS, TLS,
  HTTP types, and HTTP client modules.
- Do not introduce unused imports.

## Declarations

- Every top-level binding has an explicit type signature.
- Keep exactly one blank line between top-level declarations.
- Keep local helpers in the nearest `where` or `let` that owns them.
- Prefer domain types, records, and named helpers over tuple-heavy code when field order would be
  fragile.
- Put `deriving` on its own line for multiline type declarations, indented 2 spaces.

```hs
data AccessMode = ReadOnly
                | ReadWrite
  deriving (Eq, Show)
```

## Indentation

Use 4 spaces for expression and body indentation.

```hs
formatTarget :: Maybe String -> IO (Maybe String)
formatTarget mTarget = do
    value <- resolveTarget mTarget
    case value of
        Just host -> return $ quote host
        Nothing   -> return Nothing
```

Use 2 spaces for `where` and `deriving`.

```hs
requestHost :: Maybe String -> String
requestHost host =
    case host of
        Just h  -> h
        Nothing -> "(unknown)"
  where
    label = "request host"
```

If `if ... then ... else ...` is split across lines, keep `then` and `else` aligned with `if`.

```hs
isHealthy :: Int -> Bool
isHealthy status =
    if status < 400
    then True
    else False
```

## Alignment tokens

The alignment tokens are `=`, `->`, `::`, and `|`.

When one of these tokens is the visual anchor for neighboring lines, align it like a tabular Vim
plugin:

- Pad only before the alignment token.
- Keep exactly one space after the alignment token.
- The widest left-hand side has exactly one space before the token.
- Shorter left-hand sides may have extra spaces before the token only to reach the shared column.
- Never add extra padding after the token.

```hs
formatAuthority :: Int -> String -> String
formatAuthority port host
    | port == 80  = host
    | port == 443 = host <> ":443"
    | otherwise   = host <> ":" <> show port

readMaybeUser :: Maybe User -> String
readMaybeUser value =
    case value of
        Just user -> userName user
        Nothing   -> "(anonymous)"
```

Do not force unrelated lines into the same alignment group. Align only neighboring alternatives,
fields, guards, equations, or signatures that read as one table.

## Records and types

Use strict fields (`!`) for runtime-critical data where existing modules do: `Config`, route/proxy
settings, runtime config structures, loaded credential metadata, and similar long-lived values.

For multiline records:

- Put the opening brace on the same line as the constructor.
- Put one field per line.
- Use leading commas on fields after the first, as `stylish-haskell` emits.
- Align `::` in declarations and `=` in record construction/update using the alignment-token rule.
- Align the closing brace with the opening brace column.

```hs
data ProxySettings = ProxySettings
    { proxyAuth :: !(Maybe (BS.ByteString -> Bool))
    , wsRemote  :: !(Maybe BS.ByteString)
    , logger    :: !Logger
    }

buildProxySettings :: Logger -> Maybe BS.ByteString -> ProxySettings
buildProxySettings logger wsRemote = ProxySettings
    { proxyAuth = Nothing
    , wsRemote  = wsRemote
    , logger    = logger
    }
```

Use explicit field syntax for record construction and update when there is more than one field.

## Control flow

- Prefer pattern matching first, then guards, then ordinary expressions.
- Put `case` alternatives on separate aligned lines.
- Use guards for simple invariant checks.
- Prefer nested `case` expressions over dense conditionals when behavior branches on several
  constructors.
- Keep pure decision helpers separate from IO at the boundary that needs effects.

## Signatures, wrapping, and width

- Keep short signatures on one line.
- Split longer signatures with one argument per line and aligned arrows.
- Prefer readable `$` and `.` composition over deeply nested parentheses.
- `columns: 100` is a formatter target, not a reason for churn. Long literals, option help text,
  URLs, log messages, and single-expression declarations may stay longer when splitting them makes
  the code harder to read or grep.

```hs
runProxyServer
    :: Config
    -> Logger
    -> Settings
    -> TlsCredentialStore TLS.Credential
    -> Application
    -> IO ()
```

## Parsing, failures, and effects

- Expected parse failures return `Maybe`, `Either`, or `Either String`.
- Convert typed failures to user-visible behavior at IO boundaries.
- Do not use `error`, `fromJust`, or `head` in production paths.
- Keep validation in named helpers such as `validate...`; keep runtime builders responsible for
  applying validated config.
- Use `ByteString`/`ByteString.Char8` for request paths, headers, proxy payloads, and auth data
  already represented as bytes. Avoid unnecessary `String`/`Text` conversions.

## Logging

- Build log messages with `<>` and `toLogStr`.
- Keep logging decisions at effectful boundaries.
- Do not hide IO inside utility functions that should remain pure transformations.

## CPP and platform-specific code

- Keep CPP blocks as narrow as practical.
- Prefer CPP at module boundaries for imports and platform-specific wiring.
- Keep duplicated branches small and visually aligned.
- Preserve non-flagged behavior by default.
- After formatting, check CPP-sensitive exports/imports manually; the formatter may not preserve the
  intended conditional export surface.

## Comments and Haddock

- Use Haddock comments (`-- |`) for exported API/types.
- Use inline comments only for protocol constraints, platform constraints, or non-obvious behavior
  preservation.
- Do not restate the code in comments.
- Keep license/copyright headers intact.

## Source ordering

Prefer this stable order within a module unless another order is clearer locally:

1. Data types and type aliases.
2. Constructor/build helpers.
3. Pure utilities.
4. Effectful/IO builders.
5. Public entry points and runners.

This is a readability preference, not a compiler requirement.
