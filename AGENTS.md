# hprox Agent Guidelines

This document provides guidance for agentic coding assistants working on the hprox codebase.

## Build & Test Commands

### Build
```bash
stack build                    # Build library and executable
stack build hprox:lib         # Build only the library
stack build hprox:exe:hprox   # Build only the executable
stack build --flag hprox:quic # Build with QUIC/HTTP3 support
```

### Run Executable
```bash
stack exec hprox -- --help    # View command-line help
```

### Single Test
The project does not currently have automated tests. To validate changes:
```bash
stack build --pedantic        # Build with all warnings treated as errors
stack build --ghc-options=-Wall --ghc-options=-Werror  # Explicit strict mode
```

### Linting & Code Formatting
```bash
stylish-haskell -i src/**/*.hs     # Format all source files in-place
stylish-haskell -c src/Network/HProx.hs  # Check (don't modify) a file
```

### Check Only (No Build Artifacts)
```bash
stack ghc -- --make src/Network/HProx.hs  # Type-check without building
```

## Code Style Guidelines

### Imports
- Use **qualified imports** preferentially: `import Data.List qualified as List`
- Use `ImportQualifiedPost` extension enabled globally (see package.yaml)
- Imports are auto-formatted and grouped by stylish-haskell
- Group imports by module first component (Control.*, Data.*, Network.*, etc.)
- Separate unqualified and qualified imports with blank lines (group-based)
- List alignment: use `after_alias` style for long import lists
- Post-qualify syntax enabled: `import Data.Foo qualified as F` (not `import qualified Data.Foo as F`)

### Extensions
Default extensions enabled globally (no pragma needed):
- `ImportQualifiedPost` - allows `qualified` at end of import
- `OverloadedStrings` - string literals polymorphic for IsString types
- `RecordWildCards` - enables `{..}` in record patterns and constructions

Common additional extensions per-file:
- `ScopedTypeVariables` - for scoped type signatures
- `ViewPatterns` - for pattern guards
- `CPP` - for conditional compilation

### Formatting & Whitespace
- **Column limit**: 100 characters (enforced by stylish-haskell)
- **Indentation**: Spaces (2 spaces for module headers, 4 for import padding)
- **Line endings**: LF (Unix-style)
- **Trailing whitespace**: Remove (stylish-haskell handles this)
- **Simple alignment**: Align `=` and `->` in case statements and patterns
- **Record alignment**: Commas and braces aligned vertically

### Types & Signatures
- All top-level functions **must have explicit type signatures** (enforced by `-Wmissing-export-lists`)
- Export lists are **mandatory** for all modules (enforced by `-Wmissing-export-lists`)
- Use record syntax with field names for complex data types
- Prefer point-free style only when clarity is maintained
- Type constructors: PascalCase (e.g., `Config`, `LogLevel`)

### Naming Conventions
- **Functions**: camelCase (e.g., `runSettings`, `getTlsManager`)
- **Data types**: PascalCase (e.g., `CertFile`, `InvalidRequest`)
- **Type variables**: single lowercase letters (a, b, m) or descriptive like `addr`, `conf`
- **Module names**: PascalCase with dots (e.g., `Network.HProx.Impl`)
- **Constants**: camelCase or CAPS_CASE depending on visibility

### Error Handling
- Exceptions handled via `MonadError` or `Control.Exception`
- Use typed exceptions where possible (avoid generic `error`)
- Pattern matching on `Maybe` and `Either` preferred to exception throwing
- Custom exception types should derive from `Exception` class
- HTTP errors mapped through `Network.HTTP.Types` status codes
- Log errors before propagating (use fast-logger infrastructure)

### Records & Data
- Prefer records over tuples for functions with multiple parameters
- Use record update syntax: `config { port = 8080 }`
- Field names as lenses when appropriate (library uses record accessors, not lens library)
- Use `{..}` pattern matching with `RecordWildCards` enabled

### Module Structure
- One module per file
- Module header format (stylish-haskell enforces):
  ```haskell
  {-| Documentation comment -}
  module Network.Module
    ( exportedFunc
    , exportedType(..)
    ) where
  ```
- Private helpers listed in `other-modules` of cabal file
- Keep internal implementation modules in `src/Network/HProx/` subdirectory

### Comments & Documentation
- Haddock comments for public APIs: `-- | documentation`
- Implementation comments: `-- regular comment`
- Use Markdown in Haddock comments for readability
- Document type fields: `data Config = Config { port :: Int -- ^ Port number }`

## Compiler Warnings

All modules compiled with strict warning flags:
- `-Wall` - Most warnings
- `-Wcompat` - Compatibility warnings
- `-Wincomplete-record-updates` - Incomplete record pattern matches
- `-Wincomplete-uni-patterns` - Incomplete patterns
- `-Wmissing-export-lists` - **All modules must have explicit export lists**
- `-Wmissing-home-modules` - Missing home packages
- `-Wpartial-fields` - Partial field accessors
- `-Wredundant-constraints` - Unused type constraints

## Dependencies & Libraries

Key libraries:
- `wai` - Web application interface (HTTP abstraction)
- `warp` / `warp-tls` / `warp-quic` - HTTP server implementations
- `http-types` - HTTP types and utilities
- `http-client-tls` - HTTP client with TLS
- `conduit` - Streaming data processing
- `bytestring` - Efficient byte strings (qualified as BS8)
- `text` - Unicode text
- `crypton` - Cryptographic operations
- `tls` - TLS protocol implementation

## Special Flags

- `quic`: Enable QUIC (HTTP/3) support - adds `http3`, `quic`, `warp-quic` deps and `-DQUIC_ENABLED` CPP flag
- `static`: Enable static linking - adds `-optl-static` to ghc-options
- Platform-specific: `!os(windows)` enables Unix module and sets `-DOS_UNIX` CPP flag

## Common Tasks

### Adding a New Module
1. Create file in `src/Network/HProx/NewModule.hs` with explicit export list
2. Add to `library.exposed-modules` in package.yaml
3. Include default extensions and type signatures for all functions
4. Run `stack build` to verify no warnings
5. Run `stylish-haskell -i src/Network/HProx/NewModule.hs`

### Running with Options
```bash
# View all available options
stack exec hprox -- --help

# Run on port 8080 with basic auth
stack exec hprox -- -p 8080 -a userpass.txt

# Run with TLS on port 443
stack exec hprox -- -p 443 -s example.com:cert.pem:key.pem
```

## References
- [Hackage Documentation](https://hackage.haskell.org/package/hprox)
- [GitHub Repository](https://github.com/bjin/hprox)
- [WAI (Web Application Interface)](https://hackage.haskell.org/package/wai)
