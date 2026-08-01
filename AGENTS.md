# matrix-service agent instructions

## Scope

These instructions apply to the entire repository.

`matrix` is a standalone, dependency-free Go CLI for validating,
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
  language. Vocabularies that coupling rules depend on (severity,
  disposition, applicability, evidence status) are schema-owned.
- Keep decoding strict: any relaxation of size, depth, duplicate-member,
  unknown-field, or single-value rules is a security-relevant contract
  change.
- Rendering must stay deterministic and injection-resistant; document
  content always flows through the escaping template functions.
- `.github/workflows-staged/` holds the CI and release workflows; see its
  README for why, and keep it in sync with any pipeline change.

## Validation

Run before committing:

```sh
gofmt -l .
go vet ./...
go test -race -count=1 ./...
go run ./cmd/matrix render -config testdata/config.json -doc testdata/matrix.json -output testdata/matrix.md -check
go run ./cmd/matrix render -config testdata/config.json -doc testdata/threats.json -output testdata/threats.md -check
go run ./cmd/matrix validate -config testdata/config.json -doc testdata/threats.json -requirements testdata/matrix.json
```

If an intentional rendering change makes a golden check fail, regenerate
the affected `testdata/*.md` with the same render command without `-check`
and commit the result, noting the output change in `CHANGELOG.md`.
