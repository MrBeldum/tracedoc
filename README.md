# tracedoc

`tracedoc` is a CLI that validates, renders, and cross-version-compares
versioned governance documents:

- a **requirements traceability matrix** — normative standards decomposed
  into atomic, stably identified requirements with citations, ownership,
  planned verification, and evidence status; and
- a **system threat model** — stably identified threats with severity,
  disposition, affected assets, trust-boundary context, ownership, and
  mitigation links, including links into the requirements matrix.

The tool owns the reusable mechanics. Everything project-specific — which
standards are required, which hosts citations may reference, identifier
formats, allowed vocabularies, presentation strings — lives in a
consumer-owned [configuration file](docs/config.md), so one released tool
can serve any project without embedding its policy.

## Capabilities

- **Strict decoding** — bounded input size and nesting depth, canonical
  lowercase member names, duplicate-member rejection, unknown-field
  rejection, exactly one top-level JSON value; every document declares its
  own `document_type`.
- **Structural and cross-reference validation** — stable ID and key
  formats, citation and supersession integrity, per-type coupling rules
  (applicability/evidence for requirements; severity/disposition/mitigation
  for threats), source-host provenance, required-standard and
  asset/boundary coverage.
- **Cross-document link resolution** — a threat model's requirement links
  are resolved against the requirements matrix: unknown IDs are rejected,
  and links to retired IDs are rejected with their replacements named.
- **Cross-version baseline comparison** — a candidate document is checked
  against the designated accepted baseline: deleted or reused stable IDs
  are rejected, supersessions must be retained unchanged, and declared
  version-transition rules are enforced.
- **Deterministic Markdown rendering** — same input, same output, with
  context-aware escaping so document content cannot inject Markdown or
  HTML. Consumers may replace the per-type templates.
- **Atomic output replacement** — rendered files are written via
  same-directory temporary file and rename.

## Install

The commands below become valid once `v0.1.0` is tagged; `CHANGELOG.md`
marks the release state.

**With a Go toolchain** (Go 1.26+; toolchain auto-download normally
resolves this automatically), pin an exact release and run it through the
Go module system, which verifies the download against the Go checksum
database:

```sh
go run github.com/sofired/tracedoc/cmd/tracedoc@v0.1.0 version
```

Or install onto your PATH:

```sh
go install github.com/sofired/tracedoc/cmd/tracedoc@v0.1.0
```

**Without a Go toolchain** — for non-Go projects — every tagged release
publishes static, dependency-free binaries for linux, macOS, and windows
(amd64 and arm64) with a `SHA256SUMS` file, built by the tag-verified
release workflow:

```sh
curl -fsSLO https://github.com/sofired/tracedoc/releases/download/v0.1.0/tracedoc_0.1.0_linux_amd64
curl -fsSLO https://github.com/sofired/tracedoc/releases/download/v0.1.0/tracedoc_0.1.0_SHA256SUMS
sha256sum --check --ignore-missing tracedoc_0.1.0_SHA256SUMS
chmod +x tracedoc_0.1.0_linux_amd64 && ./tracedoc_0.1.0_linux_amd64 version
```

See [docs/versioning.md](docs/versioning.md) for the release, compatibility,
provenance, and update policy, including offline and supply-chain guidance.

## Usage

```sh
tracedoc validate -config tracedoc.config.json -doc matrix.json

tracedoc validate -config tracedoc.config.json -doc threats.json \
                -requirements matrix.json

tracedoc render   -config tracedoc.config.json -doc <document.json> \
                -output <document.md> [-template custom.md.tmpl] [-check]

tracedoc compare  -config tracedoc.config.json \
                -baseline accepted/<document.json> -candidate <document.json>

tracedoc version
```

Exit codes: `0` success; `1` validation, comparison, or freshness failure;
`2` usage, input, or internal error. The full command contract is versioned
in [docs/cli.md](docs/cli.md).

A typical continuous-integration sequence for a pull request that changes a
document:

1. `validate` the candidate (for a threat model, with `-requirements` so
   links are resolved).
2. `compare` it against the accepted baseline (for example, the document at
   the target branch head).
3. `render -check` to reject a stale committed Markdown companion.

## Concurrent changes: protect the merge, not just the pull request

`compare` proves continuity between exactly two snapshots. Two concurrent
pull requests can each be green against the same baseline and still
conflict with each other — most commonly by **allocating the same new
stable ID** for different obligations. If such a pair merges without
re-testing, the default branch ends up with a duplicate ID; the push-run
`validate` turns the branch red, and because `compare` validates its
baseline, **every later comparison fails until the branch is fixed by an
administrator merging a revert or correction past the failing check**.
Prevention is much cheaper than that cure. Consumers should enable one of:

- **"Require branches to be up to date before merging"** — the second pull
  request must rebase after the first lands, and the re-run catches the
  collision. Simplest; fine at low change volume.
- **A merge queue** — CI runs against the exact tree the default branch
  will become (current branch head plus every queued pull request), so
  cross-PR collisions are caught before anything merges, with no manual
  rebasing.

As hygiene, remember stable IDs are stable, not sequential: nothing
requires "the next number," so allocating from per-section or
per-workstream ranges makes concurrent collisions rare even before merge
protection catches them.

## Documentation

- [docs/schema.md](docs/schema.md) — shared document contract, linking to
  the [requirements](docs/schema-requirements.md) and
  [threat-model](docs/schema-threat-model.md) schemas (each version 1)
- [docs/config.md](docs/config.md) — consumer configuration reference
  (version 1)
- [docs/cli.md](docs/cli.md) — CLI contract (version 1)
- [docs/versioning.md](docs/versioning.md) — versioning, compatibility,
  release, provenance, and update policy

## Scope

`tracedoc` is repository governance tooling. It is not a runtime component
and must not be bundled into product binaries, archives, or containers. It
has no dependencies outside the Go standard library.
