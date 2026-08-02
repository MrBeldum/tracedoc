# CLI contract, version 1

The command names, flags, exit codes, and output-stream conventions below
are a versioned public contract. Within CLI contract version 1 they only
gain optional additions; renames or removals require a new contract version
and a major tool release. Human-readable message text is **not** part of the
contract and may change between releases; scripts must branch on exit codes,
not on message wording.

## Global conventions

- The command is named `tracedoc`.
- Diagnostics go to standard error, one `error: ...` line per finding.
- Success summaries go to standard output.
- All file paths are taken exactly as given (absolute or relative to the
  working directory); the tool embeds no project-specific defaults.
- Exit codes:
  - `0` — success.
  - `1` — the input was well-formed but failed validation, comparison, or a
    freshness check.
  - `2` — usage error, unreadable or lexically malformed input, an
    unidentifiable or unsupported document type, a missing configuration
    section, or an internal failure.

## Document-type dispatch

Every document declares its own type through a required top-level
`document_type` member (`"requirements"` or `"threat_model"`); there is no
type flag. The tool peeks at that member, then runs the matching schema
pipeline with the matching configuration section
([config.md](config.md)). A missing or unsupported `document_type`, or a
configuration file without the section for the document's type, is exit
`2`.

## `tracedoc validate -config <path> -doc <path> [-requirements <path>]`

Strictly decodes the configuration and the document, then validates the
document snapshot against its schema and the configured policy.

For a **threat model**, `-requirements` names the requirements matrix that
resolves the threat's requirement links. The named file must itself be a
valid requirements document under the same configuration; links must
resolve to its *active* requirement IDs, and links to retired IDs are
rejected with their replacements named. The flag is optional only when the
threat model contains no requirement links; if links exist and the flag is
absent, the command fails with exit `2` rather than silently skipping the
check. For a **requirements** document the flag is not applicable (exit
`2`).

## `tracedoc render -config <path> -doc <path> -output <path> [-template <path>] [-check]`

Validates as above (without requirement-link resolution — that is
`validate`'s responsibility), then renders the Markdown companion with the
document type's default template.

- Without `-check`, the output file is replaced atomically.
- With `-check`, nothing is written; the command fails with exit `1` when
  the output file is missing or differs from the freshly rendered text.
- With `-template`, the consumer-supplied
  [text/template](https://pkg.go.dev/text/template) file replaces the
  embedded default. The file must define a `document` template; it receives
  the document type's view data and template functions (see
  [config.md](config.md#templates)). The template file is limited to 1 MiB.
  Templates are trusted consumer input: review them like code.

## `tracedoc compare -config <path> -baseline <path> -candidate <path>`

Requires both files to declare the same document type (exit `2`
otherwise), validates both snapshots independently, then checks that the
candidate is a legal successor of the designated accepted baseline:

- every stable ID active in the baseline is still active or is retired
  through a supersession retained in the candidate;
- no ID retired in the baseline becomes active again;
- every baseline supersession is retained with an unchanged replacement-ID
  set; and
- the configured version-transition rules hold (`document_version` never
  decreases and, per configuration: any change requires a version increase,
  any change requires `last_reviewed` not to regress, and a
  `schema_version` change requires a major `document_version` increase).

`compare` never re-resolves a threat model's requirement links: baseline
links were valid against the requirements matrix of their era, and
re-checking them against today's matrix would produce false failures. CI
gets full link enforcement by running `validate -requirements` alongside
`compare`.

Note on `require_major_on_schema_change`: because `compare` validates both
snapshots first and each tool release reads exactly one schema version per
document type today, a schema-version difference cannot currently reach
this rule through the CLI. The rule is a declared forward-looking contract:
it takes effect with the first tool release that reads more than one schema
version (the planned migration mechanism in
[versioning.md](versioning.md#version-surfaces)). Tracked as
[tracedoc#4](https://github.com/sofired/tracedoc/issues/4).

`compare` evaluates exactly two snapshots. It proves continuity between the
baseline and the candidate; continuity across history follows only when
every accepted revision was compared against the previously accepted
baseline (for example, by running `compare` in CI for every change).

Two consequences for repository configuration:

- **Concurrent changes**: two branches can each pass `compare` against the
  same baseline yet conflict with each other (for example, both allocating
  the same new stable ID). Require branches to be up to date before
  merging, or use a merge queue, so the combined result is what CI tests
  (see the README's "Concurrent changes" section).
- **Recovery from an invalid accepted baseline**: `compare` validates the
  baseline and exits `1` if it is invalid, so a default branch that
  acquires an invalid document blocks every subsequent comparison —
  including the fix. This is deliberate (silently skipping the comparison
  would disable the gate exactly when it matters); repair requires an
  administrator to merge the revert or correction past the failing check.

## `tracedoc version`

Prints the tool version plus the CLI contract, per-document schema, and
configuration schema versions, then exits `0`.
