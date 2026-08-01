# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 - Unreleased

Initial release, externalized from the `tools/reqmatrix` utility in the
[Kivaar](https://github.com/sofired/kivaar) repository
([kivaar#35](https://github.com/sofired/kivaar/issues/35)).

### Added

- `validate` command: strict lexical decoding (size, depth, canonical and
  unique member names, unknown-field and trailing-value rejection) plus
  structural and cross-reference validation of matrix schema version 1.
- Consumer-owned policy configuration (version 1): required standards,
  per-standard source-host and local-path rules, milestone/issue/risk
  formats, workstream and verification-level vocabularies, presentation
  strings, and version-transition switches.
- `compare` command: cross-version enforcement between a designated
  accepted baseline and a candidate matrix — deleted-ID, reused-ID,
  dropped- and changed-supersession rejection, and configurable
  matrix-version, review-date, and schema-version transition rules.
- `render` command: deterministic, injection-resistant Markdown rendering
  with atomic output replacement, `-check` freshness verification, and
  consumer template override via `-template`.
- `version` command reporting the tool, CLI contract, matrix schema, and
  configuration schema versions.
- Versioned contracts: [docs/cli.md](docs/cli.md),
  [docs/schema.md](docs/schema.md), [docs/config.md](docs/config.md), and
  the release and update policy in [docs/versioning.md](docs/versioning.md).
