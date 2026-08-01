# reqmatrix

`reqmatrix` validates, renders, and cross-version-compares a requirements
traceability matrix: a versioned JSON document that decomposes normative
standards into atomic, stably identified requirements with citations,
ownership, planned verification, and evidence status.

The tool owns the reusable mechanics. Everything project-specific — which
standards are required, which hosts citations may reference, identifier
formats, allowed vocabularies, presentation strings — lives in a
consumer-owned [configuration file](docs/config.md), so one released tool can
serve any project without embedding its policy.

## Capabilities

- **Strict decoding** — bounded input size and nesting depth, canonical
  lowercase member names, duplicate-member rejection, unknown-field
  rejection, exactly one top-level JSON value.
- **Structural and cross-reference validation** — stable ID and key formats,
  citation and supersession integrity, applicability/evidence coupling,
  source-host provenance, required-standard coverage.
- **Cross-version baseline comparison** — a candidate matrix is checked
  against the designated accepted baseline: deleted or reused requirement
  IDs are rejected, supersessions must be retained unchanged, and declared
  version-transition rules are enforced.
- **Deterministic Markdown rendering** — same input, same output, with
  context-aware escaping so matrix content cannot inject Markdown or HTML.
  Consumers may replace the embedded template.
- **Atomic output replacement** — rendered files are written via
  same-directory temporary file and rename.

## Install

Pin an exact release and run it through the Go module system, which verifies
the download against the Go checksum database:

```sh
go run github.com/sofired/reqmatrix/cmd/reqmatrix@v0.1.0 version
```

Or install a verified binary onto your PATH:

```sh
go install github.com/sofired/reqmatrix/cmd/reqmatrix@v0.1.0
```

Building or running the tool requires Go 1.26 or later (`go.mod` declares
`go 1.26.0`; with toolchain auto-download enabled, any recent Go
installation resolves this automatically — pinned-toolchain or offline
environments must provide it themselves).

See [docs/versioning.md](docs/versioning.md) for the release, compatibility,
provenance, and update policy, including offline and supply-chain guidance.

## Usage

```sh
reqmatrix validate -config reqmatrix.config.json -matrix matrix.json

reqmatrix render   -config reqmatrix.config.json -matrix matrix.json \
                   -output matrix.md [-template custom.md.tmpl] [-check]

reqmatrix compare  -config reqmatrix.config.json \
                   -baseline accepted/matrix.json -candidate matrix.json

reqmatrix version
```

Exit codes: `0` success; `1` validation, comparison, or freshness failure;
`2` usage, input, or internal error. The full command contract is versioned
in [docs/cli.md](docs/cli.md).

A typical continuous-integration sequence for a pull request that changes
`matrix.json`:

1. `validate` the candidate matrix.
2. `compare` it against the accepted baseline (for example, the matrix at
   the target branch head).
3. `render -check` to reject a stale committed Markdown companion.

## Documentation

- [docs/schema.md](docs/schema.md) — matrix document schema (version 1)
- [docs/config.md](docs/config.md) — consumer configuration reference
  (version 1)
- [docs/cli.md](docs/cli.md) — CLI contract (version 1)
- [docs/versioning.md](docs/versioning.md) — versioning, compatibility,
  release, provenance, and update policy

## Scope

`reqmatrix` is repository governance tooling. It is not a runtime component
and must not be bundled into product binaries, archives, or containers. It
has no dependencies outside the Go standard library.
