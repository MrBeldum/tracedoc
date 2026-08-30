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
the authoritative list of these commands; if the two diverge, CI is
correct.
