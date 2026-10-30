# real-http2-server — GO-2023-2102 (stdlib toolchain boundary)

- **Advisory shape**: OSV lists `stdlib` first, then `golang.org/x/net`;
  the stdlib entry applies to the *release toolchain*, not a dep pin.
- **Product**: `products/http2-server` — `http.Server.ListenAndServeTLS`.
- **Truth**: INCONCLUSIVE. The generated fixture carries only a `go 1.23`
  minimum; the toolchain that actually built a release is not evidenced in a
  synthetic product, and `go.mod` is a minimum, not a build fact. Resolving
  the stdlib range against the analysis toolchain (or the go.mod directive)
  would be a false-safe, so applicability stays undecidable and the case
  abstains. A product that pins its release toolchain (toolchain directive,
  Dockerfile, CI, or `--release-go-version`) resolves to NOT_AFFECTED when
  that version is past both fixed ranges.
