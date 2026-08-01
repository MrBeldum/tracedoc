# reqmatrix agent instructions

## Scope

These instructions apply to the entire repository.

`reqmatrix` is a standalone, dependency-free Go CLI for validating,
rendering, and cross-version-comparing requirements-traceability matrices.
It owns reusable mechanics only; project policy belongs in consumer
configuration files, never in this codebase.

## Constraints

- Go standard library only. Do not add module dependencies; CI enforces an
  empty dependency graph and the absence of `go.sum`.
- The CLI contract ([docs/cli.md](docs/cli.md)), matrix schema
  ([docs/schema.md](docs/schema.md)), and configuration schema
  ([docs/config.md](docs/config.md)) are versioned public contracts. Apply
  the compatibility rules in [docs/versioning.md](docs/versioning.md) before
  changing accepted inputs, exit codes, or rendered output.
- Do not add consumer-specific policy (standard lists, hosts, vocabularies,
  URLs) to Go code or the default template. New policy needs must become new
  bounded configuration members — never a general-purpose rule language.
- Keep decoding strict: any relaxation of size, depth, duplicate-member,
  unknown-field, or single-value rules is a security-relevant contract
  change.
- Rendering must stay deterministic and injection-resistant; matrix content
  always flows through the escaping template functions.

## Validation

Run before committing:

```sh
gofmt -l .
go vet ./...
go test -race -count=1 ./...
go run ./cmd/reqmatrix render -config testdata/config.json -matrix testdata/matrix.json -output testdata/matrix.md -check
```

If an intentional rendering change makes the golden check fail, regenerate
`testdata/matrix.md` with the same command without `-check` and commit the
result, noting the output change in `CHANGELOG.md`.
