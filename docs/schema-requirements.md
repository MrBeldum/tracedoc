# Requirements-matrix schema, version 1

The matrix is a single JSON object with
`"document_type": "requirements"`. It obeys the
[shared lexical contract and structural conventions](schema.md); this
document specifies the requirements-specific members.

## Top level

| Member             | Type   | Rules                                          |
| ------------------ | ------ | ---------------------------------------------- |
| `document_type`    | string | must be `"requirements"`                       |
| `schema_version`   | number | must be `1`                                    |
| `document_version` | string | Semantic Versioning 2.0.0                      |
| `last_reviewed`    | string | RFC 3339 full date                             |
| `standards`        | array  | non-empty; see below                           |
| `requirements`     | array  | non-empty; see below                           |
| `supersessions`    | array  | shared supersession rules with requirement IDs |

## `standards[]`

| Member  | Type   | Rules                                                            |
| ------- | ------ | ---------------------------------------------------------------- |
| `key`   | string | `^[A-Z][A-Z0-9]*(?:[-.][A-Z0-9]+)*$`, unique                     |
| `title` | string | non-empty                                                        |
| `uri`   | string | must satisfy the configured source policy for `key` (host or exact local path) |

Every declared standard must be cited by at least one requirement, and every
standard named in the configuration's `requirements.required_standards`
must be declared.

## `requirements[]`

| Member                    | Type   | Rules                                                              |
| ------------------------- | ------ | ------------------------------------------------------------------ |
| `id`                      | string | stable-ID format, unique, never renumbered or reused               |
| `title`                   | string | non-empty                                                          |
| `standard`                | string | a declared standard key (the primary source)                       |
| `citations`               | array  | non-empty; each cites a declared standard with a non-empty `clause` and a policy-conforming `uri`; no duplicates; at least one citation must reference the primary standard |
| `interpretation`          | string | non-empty                                                          |
| `applicability`           | string | `applicable`, `deferred`, or `not-applicable`                      |
| `applicability_rationale` | string | required when not `applicable`; optional otherwise                 |
| `owner`                   | object | `milestone` (configured pattern), optional `issue` (configured pattern, nullable), `workstream` (configured vocabulary) |
| `planned_verification`    | object | `levels`: non-empty, values from the configured vocabulary; `evidence`: non-empty list of identifiers |
| `evidence_status`         | string | `planned`, `in-progress`, `verified`, `deferred`, or `not-applicable` |
| `traceability`            | object | `adrs`, `threats`, `risks`: required arrays, may be empty; `risks` values match the configured pattern |

Applicability and evidence status are coupled: a `deferred` requirement must
have `deferred` evidence status, a `not-applicable` requirement must have
`not-applicable` status, and an `applicable` requirement may not use either.

### Known schema-1 limitation: chained supersessions

Because `replacement_ids` must reference *active* IDs, retiring a
requirement that is itself listed as a replacement in an older supersession
cannot be expressed without editing that older entry — which the `compare`
command rejects. Schema 1 therefore does not support retiring a replacement
requirement. Lifting this restriction is a schema-2 candidate; until then,
split or merge obligations without retiring IDs that appear in
`replacement_ids`.
