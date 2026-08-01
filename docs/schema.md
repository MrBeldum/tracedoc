# Matrix document schema, version 1

The matrix is a single JSON object. `schema_version` identifies this schema;
this tool release reads version `1` only. Schema changes follow the policy
in [versioning.md](versioning.md).

## Lexical contract

Every matrix document must satisfy, before structural validation:

- at most 8 MiB;
- nesting depth at most 16;
- object member names match `^[a-z][a-z0-9_]*$`;
- no duplicate member names within an object;
- no members outside this schema; and
- exactly one top-level JSON value.

Every validated string field is limited to 16 KiB. All string fields are
plain text: authored Markdown and HTML are not supported, and the renderer
escapes content so it cannot introduce Markdown structure or raw HTML.

## Top level

| Member           | Type   | Rules                                                        |
| ---------------- | ------ | ------------------------------------------------------------ |
| `schema_version` | number | must be `1`                                                  |
| `matrix_version` | string | Semantic Versioning 2.0.0                                    |
| `last_reviewed`  | string | RFC 3339 full date (`YYYY-MM-DD`)                            |
| `standards`      | array  | non-empty; see below                                         |
| `requirements`   | array  | non-empty; see below                                         |
| `supersessions`  | array  | required, may be empty; append-only across accepted revisions |

## `standards[]`

| Member  | Type   | Rules                                                            |
| ------- | ------ | ---------------------------------------------------------------- |
| `key`   | string | `^[A-Z][A-Z0-9]*(?:[-.][A-Z0-9]+)*$`, unique                     |
| `title` | string | non-empty                                                        |
| `uri`   | string | must satisfy the configured source policy for `key` (host or exact local path) |

Every declared standard must be cited by at least one requirement, and every
standard named in the configuration's `required_standards` must be declared.

## `requirements[]`

| Member                    | Type   | Rules                                                              |
| ------------------------- | ------ | ------------------------------------------------------------------ |
| `id`                      | string | `^[A-Z][A-Z0-9]*-[0-9]{3}$`, unique, never renumbered or reused    |
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

## `supersessions[]`

| Member            | Type   | Rules                                                       |
| ----------------- | ------ | ----------------------------------------------------------- |
| `retired_id`      | string | requirement-ID format, unique, must not be an active ID     |
| `replacement_ids` | array  | non-empty; every entry must be an active requirement ID     |
| `rationale`       | string | non-empty                                                   |

### Known schema-1 limitation: chained supersessions

Because `replacement_ids` must reference *active* IDs, retiring a
requirement that is itself listed as a replacement in an older supersession
cannot be expressed without editing that older entry — which the `compare`
command rejects. Schema 1 therefore does not support retiring a replacement
requirement. Lifting this restriction is a schema-2 candidate; until then,
split or merge obligations without retiring IDs that appear in
`replacement_ids`.

## Cross-version rules

One snapshot cannot prove that an ID was never deleted or reused across
revisions. The `compare` command enforces those guarantees between the
designated accepted baseline and a candidate; see
[cli.md](cli.md#reqmatrix-compare--config-path--baseline-path--candidate-path).
