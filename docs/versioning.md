# Versioning, release, provenance, and update policy

## Version surfaces

`reqmatrix` carries four versioned surfaces, reported by
`reqmatrix version`:

| Surface               | Declared in                     | Compatibility rule                                                   |
| --------------------- | ------------------------------- | -------------------------------------------------------------------- |
| Tool release          | git tag `vX.Y.Z`                | Semantic Versioning for every guarantee below                        |
| CLI contract          | [cli.md](cli.md)                | additive within a contract version; breaking changes bump the tool major version |
| Matrix schema         | [schema.md](schema.md)          | one schema version per document; a new schema version bumps the tool major version, and the tool states which schema versions it reads |
| Configuration schema  | [config.md](config.md)          | same policy as the matrix schema                                     |

Within a tool major version:

- **Patch** releases fix defects without changing accepted inputs or
  rendered bytes for previously valid inputs, except where the previous
  behavior was itself a defect (documented in the changelog).
- **Minor** releases may add commands, flags, optional configuration
  members, and template data, and may change rendered output. A consumer
  that pins an exact version is unaffected until it updates, and
  `render -check` makes any output change visible at update time.
- **Major** releases may change the CLI contract, schema versions, or
  validation strictness in breaking ways, with migration notes in the
  changelog.

Version `0.y.z` follows the same discipline with reduced stability
promises: minor releases may break, and the changelog records every break.

## Release process

1. Update `CHANGELOG.md` and the `toolVersion` constant in
   `cmd/reqmatrix/main.go` to the release version.
2. CI must be green (formatting, `go vet`, race-enabled tests, tidy and
   dependency-free module checks).
3. Tag the release commit `vX.Y.Z`. The tag push triggers the
   release-verification workflow, which re-runs the full verification suite
   against the tagged commit and fails if the embedded `toolVersion` does
   not match the tag.
4. After the release-verification workflow succeeds, create a GitHub
   release pointing at the tag with the changelog entry. A tag whose
   verification failed must never be announced or consumed; publish a
   higher corrected version instead (tags are immutable once pushed).

Releases are source releases distributed through the Go module ecosystem;
no binaries are published. The Go module checksum database
(`sum.golang.org`) records the hash of every published version, making
releases tamper-evident and immutable: retracting a bad release means
publishing a new version, never moving a tag.

## Consumer pinning and verification

Pin an exact version in the invocation (or in a `go.mod` of a dedicated
tools module) and let the Go toolchain verify it:

```sh
go run github.com/sofired/reqmatrix/cmd/reqmatrix@v0.1.0 ...
```

- `go run`/`go install` with an explicit `@vX.Y.Z` resolve through the
  module proxy and verify the download against the checksum database by
  default. Do not disable `GOSUMDB`.
- For a stronger, repository-recorded pin, add the module to a dedicated
  tools `go.mod`; the accompanying `go.sum` then records the expected hash
  in the consuming repository itself.
- The tool must not be vendored into product binaries, archives, or
  containers; it is repository tooling only.

## Update policy

- Consumers update by changing the pinned version in one place and
  re-running their matrix checks; `render -check` surfaces rendering
  differences, and validation surfaces strictness changes.
- Enable automated dependency-update tooling (for example Dependabot on the
  pinned invocation or tools module) so security and correctness fixes
  arrive promptly; review the changelog before accepting a major update.

## Offline, availability, and supply-chain implications

- Resolving `module@version` requires network access to the module proxy on
  first use per machine. CI caches (`GOMODCACHE`, `actions/setup-go` module
  caching) remove the dependency on the proxy for warm builds.
- Fully offline or air-gapped environments can point `GOPROXY` at an
  internal proxy that mirrors the module, or vendor the tool in a dedicated
  tools module inside the consuming repository — keeping it out of product
  artifacts.
- The tool itself has no dependencies outside the Go standard library, so
  its supply-chain surface is the Go toolchain, the module proxy, and this
  repository. The checksum database protects against a compromised proxy;
  repository compromise is mitigated by review of version bumps in the
  consuming repository (a new version's behavior is visible in its diff and
  changelog, and the pinned hash changes in review).
