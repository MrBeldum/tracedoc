# Threat-model schema, version 1

The threat model is a single JSON object with
`"document_type": "threat_model"`. It obeys the
[shared lexical contract and structural conventions](schema.md); this
document specifies the threat-model-specific members.

## Top level

| Member             | Type   | Rules                                     |
| ------------------ | ------ | ----------------------------------------- |
| `document_type`    | string | must be `"threat_model"`                  |
| `schema_version`   | number | must be `1`                               |
| `document_version` | string | Semantic Versioning 2.0.0                 |
| `last_reviewed`    | string | RFC 3339 full date                        |
| `assets`           | array  | non-empty; see below                      |
| `trust_boundaries` | array  | non-empty; see below                      |
| `threats`          | array  | non-empty; see below                      |
| `supersessions`    | array  | shared supersession rules with threat IDs |

## `assets[]` and `trust_boundaries[]`

| Member        | Type   | Rules                                                     |
| ------------- | ------ | --------------------------------------------------------- |
| `id`          | string | assets: `^AST-[0-9]{3}$`; boundaries: `^TB-[0-9]{3}$`; unique |
| `name`        | string | non-empty                                                 |
| `description` | string | non-empty                                                 |

Every declared asset and trust boundary must be referenced by at least one
threat; enumerations do not carry dead entries.

## `threats[]`

| Member                   | Type   | Rules                                                            |
| ------------------------ | ------ | ---------------------------------------------------------------- |
| `id`                     | string | stable-ID format, unique, never reused; must not use the `AST-`/`TB-` prefixes |
| `title`                  | string | non-empty                                                        |
| `description`            | string | non-empty                                                        |
| `severity`               | string | `critical`, `high`, `medium`, or `low` (schema-owned)            |
| `disposition`            | string | `open`, `mitigated`, `accepted`, `transferred`, or `avoided` (schema-owned) |
| `disposition_rationale`  | string | required for `accepted`, `transferred`, and `avoided`; optional otherwise |
| `affected_assets`        | array  | non-empty, unique, declared asset IDs                            |
| `trust_boundaries`       | array  | required, may be empty, unique, declared boundary IDs            |
| `owner`                  | object | always required: `milestone` (configured pattern), optional `issue` (configured pattern, nullable), `workstream` (configured vocabulary) |
| `mitigations`            | object | see below                                                        |

`owner` and `disposition` are unconditionally required, which subsumes the
common governance rule that no critical or high threat lacks an owner and
an explicit disposition (`open` is the explicit not-yet-handled value, not
an omission).

### `mitigations`

Required object with four required arrays (each may be empty, entries
unique):

| Member         | Rules                                                             |
| -------------- | ----------------------------------------------------------------- |
| `adrs`         | decision-record identifiers (free-form, bounded)                  |
| `requirements` | requirement IDs (stable-ID format); resolved against the requirements matrix by `validate -requirements` — links must name *active* requirement IDs, and links to retired IDs are rejected with their replacements named |
| `tests`        | planned test or evidence identifiers (free-form, bounded)         |
| `risks`        | risk-record identifiers matching the configured `risk_pattern`    |

Disposition coupling:

- `mitigated` requires at least one entry across `adrs`, `requirements`,
  and `tests`.
- `accepted` requires at least one `risks` entry (the record that carries
  the acceptance) in addition to the rationale.

## Severity and disposition vocabularies are schema-owned

The severity and disposition enums are part of this schema rather than
consumer configuration because the coupling rules above depend on their
exact values. Changing the vocabularies is a schema revision, not a config
edit — the same policy-versus-mechanics boundary that keeps a
general-purpose rule language out of the configuration.
