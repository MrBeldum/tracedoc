# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changed

- **Threat-model schema (breaking, pre-adoption).** The threat model
  expands from a list of threats into a reviewable architecture-level
  model, in place, keeping `document_type`, `schema_version` 1,
  `config_version` 1, and CLI contract 1
  ([#7](https://github.com/sofired/tracedoc/issues/7)). No released
  consumer had adopted the previous shape.

  Added to the document: `status`, accountable `owner`, `summary`, `scope`,
  `assumptions`, `open_questions`, `diagrams`, `components`, `actors`,
  `attacker_model`, `data_flows`, `entry_points`, `decisions`, `risks`,
  `controls`, `planned_evidence`, and `observability`. Assets gain
  `objective`; trust boundaries gain endpoints, data, channels, planned
  guarantees, validation, implementation state, and evidence.

  Threats replace `description` with `source`, `prerequisites`, `action`,
  `impact`, and an ordered `abuse_path`, and add `likelihood`, `severity`,
  and `priority` with rationales, `residual_risk`, `existing_controls`,
  `gaps`, `recommended_mitigations`, `detection_ideas`, and typed link
  lists for actors, assets, boundaries, flows, controls, risks, and planned
  evidence.

  - `disposition` becomes `treatment`, and its vocabulary changes from the
    outcome states `open`/`mitigated`/`accepted`/`transferred`/`avoided`
    to the decisions `mitigate`/`accept`/`avoid`/`transfer`. A threat now
    records what the project decided, not what has already happened.
  - `severity` narrows to `low`/`medium`/`high`; the former `critical`
    level moves to the new `priority` vocabulary, which is derived from
    likelihood and severity together.
  - `owner` gains a required `principal`, separating the accountable
    person from the milestone, issue, and workstream that route the work.
  - The `mitigations` object is removed. Requirement links move to
    `controls[].requirement_links`, so a requirement obliges the control
    that handles a threat rather than the threat itself.
  - Every array member must be present, even when empty, because `compare`
    distinguishes an omitted array from an empty one.

- **Coverage is credited only from threats.** Declared assets, boundaries,
  flows, controls, and risks must be linked by a threat, and threats by
  planned evidence. References from the architecture graph to its own
  members no longer count, which previously would have made the rules
  vacuously true.

- **Configuration.** New top-level `owner_pattern`. The `threat_model`
  section gains `document_statuses`, `control_statuses`, `evidence_levels`,
  `evidence_statuses`, `reference_hosts`, and a `coverage` object of named
  switches.

### Added

- Entry-point coverage: an entry point counts as analysed only when one
  threat both crosses its trust boundary and travels one of its data flows.
  Matching either half alone is rejected as a false positive that would
  certify an unreviewed surface.
- Document-wide identifier uniqueness across every declared collection, so
  a reused ID cannot collapse two anchors in the rendered companion.
- Provenance-checked references for diagrams, decisions, and risks: exactly
  one of a repository-relative `path` or an HTTPS `url` on a host declared
  in the new `reference_hosts` allowlist. Diagram generation and
  diagram-source parsing remain out of scope.
- `check.LexicalURI` and `check.RepoRelativePath`, so both document types
  share one definition of a safe reference rather than drifting apart.

## 0.1.0 - 2026-08-02

Initial release. The requirements-matrix mechanics were externalized from
the `tools/reqmatrix` utility in the
[Kivaar](https://github.com/sofired/kivaar) repository
([kivaar#35](https://github.com/sofired/kivaar/issues/35)); the
threat-model document type was added for
[kivaar#5](https://github.com/sofired/kivaar/issues/5) (tracked as
[#2](https://github.com/sofired/tracedoc/issues/2)) before the first
tag, so the multi-document design ships from the start.

### Added

- Document-type-generic `tracedoc` CLI: every document declares a required
  top-level `document_type`; `validate`, `render`, and `compare` dispatch
  on it, and `compare` requires matching types.
- Requirements-matrix schema v1: strict lexical decoding (size, depth,
  canonical and unique member names, unknown-field and trailing-value
  rejection) plus structural and cross-reference validation under
  consumer policy (required standards, per-standard source-host and
  local-path rules, verification-level vocabulary).
- Threat-model schema v1: assets, trust boundaries, and threats with
  schema-owned severity and disposition vocabularies, disposition
  coupling rules (rationale for accepted/transferred/avoided, mitigation
  evidence for mitigated, risk records for accepted), unconditional
  ownership, coverage rules for declared assets and boundaries, and the
  shared append-only supersession ledger. Ledger entries either name their
  active replacements or carry an explicitly empty replacement list to
  record withdrawal without a successor; withdrawals are immutable like
  every other entry.
- Cross-document link resolution: `validate -requirements` resolves a
  threat model's requirement links against a validated requirements
  matrix, rejecting unknown IDs and retired IDs (naming replacements);
  the flag is mandatory whenever links exist.
- Cross-version `compare` for both document types: deleted-ID, reused-ID,
  dropped- and changed-supersession rejection, and configurable
  document-version, review-date, and schema-version transition rules.
- Deterministic, injection-resistant Markdown rendering with per-type
  default templates, consumer template override via `-template`, `-check`
  freshness verification, and atomic output replacement.
- Single consumer configuration (version 1): shared project settings
  (owner/risk formats, workstreams, issue URL base, generator name,
  version-transition switches) plus per-document-type sections.
- `version` command reporting the tool, CLI contract, both document
  schemas, and configuration schema versions.
- Versioned contracts: [docs/cli.md](docs/cli.md),
  [docs/schema.md](docs/schema.md) (with per-type schema documents),
  [docs/config.md](docs/config.md), and the release and update policy in
  [docs/versioning.md](docs/versioning.md), including tag-triggered
  release verification.
- Binary distribution for non-Go consumers: the release workflow
  cross-compiles static binaries (linux, macOS, windows; amd64 and arm64)
  from the verified tag, generates a `SHA256SUMS` file, and attaches both
  to a draft GitHub release.

### Fixed (pre-release review hardening)

Defects found and fixed by multi-agent review before the first tag; none
ever shipped in a release:

- Link destinations percent-encode every control rune and the Unicode
  line and paragraph separators, closing a demonstrated Markdown
  structure-injection path and making the escape safe by construction.
- Every validated string — scalar fields and every free-form list item
  alike — is checked non-blank, bounded, and free of control and
  line-separator characters before any consumer-configured pattern runs,
  so permissive patterns can no longer admit values the renderer must not
  receive.
- Every escaping function neutralizes control runes, line and paragraph
  separators, and bidirectional overrides, so no document field can carry
  a terminal escape sequence or reorder surrounding text in generated
  Markdown regardless of which context it is emitted in.
- Renderers return a descriptive error instead of panicking when handed a
  document that skipped validation.
- Semantic-version components are compared as strings, eliminating an
  integer-overflow conflation of distinct oversized versions.
- A citation naming an unknown standard keeps its lexical URI checks and
  no longer cascades a redundant policy diagnostic.
