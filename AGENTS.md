# tracedoc agent instructions

## Scope

These instructions apply to the entire repository.

`tracedoc` is a standalone, dependency-free Go CLI for validating,
rendering, and cross-version-comparing governance documents (requirements
matrices and system threat models). It owns reusable mechanics only;
project policy belongs in consumer configuration files, never in this
codebase.

## Constraints

- Go standard library only. Do not add module dependencies; CI enforces an
  empty dependency graph and the absence of `go.sum`.
- The CLI contract ([docs/cli.md](docs/cli.md)), document schemas
  ([docs/schema.md](docs/schema.md)), and configuration schema
  ([docs/config.md](docs/config.md)) are versioned public contracts. Apply
  the compatibility rules in [docs/versioning.md](docs/versioning.md) before
  changing accepted inputs, exit codes, or rendered output.
- Do not add consumer-specific policy (standard lists, hosts, vocabularies,
  URLs) to Go code or the default templates. New policy needs must become
  new bounded configuration members — never a general-purpose rule
  language. The dividing line is whether a validation rule keys off the
  value: vocabularies that coupling or coverage rules depend on
  (applicability, evidence status, likelihood, severity, priority,
  treatment, decision status) are schema-owned, while vocabularies that
  merely describe a project's workflow (document, control, and evidence
  statuses; evidence levels) are configuration.
- Keep decoding strict: any relaxation of size, depth, duplicate-member,
  unknown-field, or single-value rules is a security-relevant contract
  change.
- Rendering must stay deterministic and injection-resistant; document
  content always flows through the escaping template functions.
- `.github/workflows/` holds the CI and release workflows.
- Documentation is gated, not advisory: `internal/docscheck` fails the
  test suite on a dead internal link or anchor, on a backticked repository
  path named in prose that does not exist, on a changelog section with no
  correctly dated entry for the released version, and on self-check command
  lists that have drifted apart. See [Documentation checks](#documentation-checks).

## Validation

Run before committing:

```sh
gofmt -l .
go vet ./...
go test -race -count=1 ./...
go run ./cmd/tracedoc validate -config testdata/config.json -doc testdata/matrix.json
go run ./cmd/tracedoc render -config testdata/config.json -doc testdata/matrix.json -output testdata/matrix.md -check
go run ./cmd/tracedoc compare -config testdata/config.json -baseline testdata/matrix.json -candidate testdata/matrix.json
go run ./cmd/tracedoc validate -config testdata/config.json -doc testdata/threats.json -requirements testdata/matrix.json
go run ./cmd/tracedoc render -config testdata/config.json -doc testdata/threats.json -output testdata/threats.md -check
go run ./cmd/tracedoc compare -config testdata/config.json -baseline testdata/threats.json -candidate testdata/threats.json
```

If an intentional rendering change makes a golden check fail, regenerate
the affected `testdata/*.md` with the same render command without `-check`
and commit the result, noting the output change in `CHANGELOG.md`.

The "Self-check fixture documents" step in `.github/workflows/ci.yml` is
the authoritative list of these commands. They are no longer allowed to
diverge: `internal/docscheck` asserts that this block and both workflows
run the same commands in the same order, so a change to one that misses
the others fails the test suite.

### Documentation checks

`internal/docscheck` treats this repository's own Markdown as testable.
The `go test` line above already runs it; to run only these checks, or to
read a failure on its own:

```sh
go test ./internal/docscheck/
```

It fails the build when a relative Markdown link or `#anchor` does not
resolve, when a backticked repository path named in prose does not exist,
when `CHANGELOG.md` has no section dated `YYYY-MM-DD` for the version
`cmd/tracedoc/main.go` reports, or when the self-check command lists
above have drifted apart. In CI these run inside the existing
"Test with race detector" step, as `TestRepositoryDocumentation`.

Fixing a failure means correcting the claim, not the checker: repoint the
link, restore the path, date the changelog section, or bring the command
lists back together. The checker is deliberately conservative about what
it treats as a repository path — a backticked candidate must contain a
slash, carry no glob or shell metacharacters, and begin with a segment
that names a real entry at the repository root — so a false report is
more likely a real mistake than a checker bug. Its known blind spots are
listed in the package comment.

These checks cover claims that are mechanically false, never writing
quality. A claim about *behavior* — that a template anchors every entity,
that a field rejects control characters — is beyond the reach of any
documentation linter and belongs in a test next to the behavior it
describes.
