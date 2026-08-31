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

Every declared standard must be the primary standard of at least one
requirement, and every standard named in the configuration's
`requirements.required_standards` must be declared.

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
| `owner`                   | object | see [Ownership](#ownership)                                       |
| `planned_verification`    | object | `levels`: non-empty, values from the configured vocabulary; `evidence`: non-empty list of identifiers, see [Evidence](#evidence) |
| `evidence_status`         | string | `planned`, `in-progress`, `verified`, `deferred`, or `not-applicable` |
| `traceability`            | object | see [Traceability](#traceability)                                 |

Applicability and evidence status are coupled: a `deferred` requirement must
have `deferred` evidence status, a `not-applicable` requirement must have
`not-applicable` status, and an `applicable` requirement may not use either.

### Known schema-1 limitation: chained supersessions

Because every `replacement_ids` entry must reference an *active* ID,
retiring a requirement that is itself listed as a replacement in an older
supersession cannot be expressed without editing that older entry — which
the `compare` command rejects. Schema 1 therefore does not support retiring
a replacement requirement. Lifting this restriction is a schema-2
candidate; until then, split or merge obligations without retiring IDs that
appear in `replacement_ids`. (Withdrawing an obligation outright is fully
supported: retire it with an empty replacement list and a rationale.)
Tracked as [tracedoc#3](https://github.com/sofired/tracedoc/issues/3).

## Traceability

| Member    | Rules                                                              |
| --------- | ------------------------------------------------------------------ |
| `adrs`    | required array, may be empty; free-form bounded identifiers         |
| `threats` | required array, may be empty; free-form bounded identifiers         |
| `risks`   | required array, may be empty; matches the configured `risk_pattern` |

Every entry in all three is non-blank, bounded, unique within its list, and
free of [invisible code points](schema.md#invisible-code-points), like any
declared string list.

`adrs` and `threats` have **no format rule and are not resolved**, which is
deliberate rather than an omission. A requirements matrix is validated on
its own: nothing passes a threat model alongside it, and the
`validate -requirements` flag runs the other way — it lets a *threat model*
resolve its requirement links against a matrix, not the reverse. Imposing
a threat-ID format here would assert a shape this tool has no way to check,
which is worse than saying plainly that these are free text.

If you want a requirement's threats verified, express the relationship from
the threat-model side, where `controls[].requirement_links` is resolved
against the matrix and a link to an unknown or retired requirement is
rejected.

`risks` carries a format because `risk_pattern` describes the project's own
risk register, which the consumer has already declared in configuration.

## Ownership

| Member       | Type           | Rules                                |
| ------------ | -------------- | ------------------------------------ |
| `milestone`  | string         | matches `milestone_pattern`          |
| `issue`      | string \| null | matches `issue_pattern` when present |
| `workstream` | string         | configured `workstreams` vocabulary  |

`milestone` and `issue` are each first checked non-blank, bounded, and free
of [invisible code points](schema.md#invisible-code-points), *then* matched
against the configured pattern, so a permissive consumer pattern cannot
admit a value the renderer must not receive. `workstream` is checked by
membership alone, which needs no lexical pass because a closed vocabulary
cannot carry a value the project did not write.

This object carries **routing only**. Unlike the threat model's
[owner](schema-threat-model.md#ownership), it has no accountable
`principal`: a requirement records an obligation the project has taken on,
and the milestone and workstream say when and where it will be met. A
threat records residual risk somebody has to carry, which is why that
document type names a person and this one does not. `owner_pattern` is
configured in the threat-model section for the same reason.

## Evidence

`planned_verification.evidence` is a non-empty list of free-form bounded
identifiers naming what will demonstrate the requirement is met, and
`evidence_status` records how far that has got.

This is **not** the threat model's
[`planned_evidence[]`](schema-threat-model.md#planned_evidence), despite the
shared word. That collection declares records with identifiers, levels,
owners, and resolved threat links; this is a list of names. Nothing links
the two, and an entry here is never resolved against one there.

The same distinction applies in configuration: `verification_levels` and
`evidence_levels` are separate vocabularies for separate document types.
They may happen to hold the same values in a project that uses the same
words for both, but neither is derived from the other, and changing one
does not affect the other.
