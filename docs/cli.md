# CLI contract, version 1

The command names, flags, exit codes, and output-stream conventions below
are a versioned public contract. Within CLI contract version 1 they only
gain optional additions; renames or removals require a new contract version
and a major tool release. Human-readable message text is **not** part of the
contract and may change between releases; scripts must branch on exit codes,
not on message wording.

## Global conventions

- Diagnostics go to standard error, one `error: ...` line per finding.
- Success summaries go to standard output.
- All file paths are taken exactly as given (absolute or relative to the
  working directory); the tool embeds no project-specific defaults.
- Exit codes:
  - `0` — success.
  - `1` — the input was well-formed but failed validation, comparison, or a
    freshness check.
  - `2` — usage error, unreadable or lexically malformed input, or an
    internal failure.

## `reqmatrix validate -config <path> -matrix <path>`

Strictly decodes the configuration and the matrix, then validates the
matrix snapshot against the schema and the configured policy.

## `reqmatrix render -config <path> -matrix <path> -output <path> [-template <path>] [-check]`

Validates as above, then renders the Markdown companion.

- Without `-check`, the output file is replaced atomically.
- With `-check`, nothing is written; the command fails with exit `1` when
  the output file is missing or differs from the freshly rendered text.
- With `-template`, the consumer-supplied
  [text/template](https://pkg.go.dev/text/template) file replaces the
  embedded default. The file must define a `matrix` template; it receives
  the same data and functions as the default template (see
  [docs/config.md](config.md#templates)). Templates are trusted consumer
  input: review them like code.

## `reqmatrix compare -config <path> -baseline <path> -candidate <path>`

Validates both snapshots independently, then checks that the candidate is a
legal successor of the designated accepted baseline:

- every requirement ID active in the baseline is still active or is retired
  through a supersession retained in the candidate;
- no requirement ID retired in the baseline becomes active again;
- every baseline supersession is retained with an unchanged replacement-ID
  set; and
- the configured version-transition rules hold (`matrix_version` never
  decreases and, per configuration: any change requires a version increase,
  any change requires `last_reviewed` not to regress, and a
  `schema_version` change requires a major `matrix_version` increase).

Note on `require_major_on_schema_change`: because `compare` validates both
snapshots first and each tool release reads exactly one matrix schema
version today, a schema-version difference cannot currently reach this rule
through the CLI. The rule is a declared forward-looking contract: it takes
effect with the first tool release that reads more than one schema version
(the planned migration mechanism in
[versioning.md](versioning.md#version-surfaces)).

`compare` evaluates exactly two snapshots. It proves continuity between the
baseline and the candidate; continuity across history follows only when
every accepted revision was compared against the previously accepted
baseline (for example, by running `compare` in CI for every change).

## `reqmatrix version`

Prints the tool version plus the CLI contract, matrix schema, and
configuration schema versions, then exits `0`.
