# Consumer configuration, version 1

The configuration file carries every project-specific rule the tool
applies. It is a bounded set of declarative knobs, deliberately not a
general-purpose validation language: new kinds of rules require a tool
change and a configuration schema revision, not cleverer configuration.

The file obeys the same lexical contract as the matrix (strict decoding,
canonical member names, unknown members rejected) with a 1 MiB size limit.

Example:

```json
{
  "config_version": 1,
  "required_standards": ["EXAMPLE-CORE", "LOCAL-PLAN"],
  "standard_sources": [
    { "key": "EXAMPLE-CORE", "host": "standards.example.org" },
    { "key": "LOCAL-PLAN", "path": "../plan.md" }
  ],
  "milestone_pattern": "^M(?:[0-9]|1[01])$",
  "issue_pattern": "^#[1-9][0-9]*$",
  "risk_pattern": "^R(?:[1-9]|1[0-2])$",
  "workstreams": ["Protocol", "Platform"],
  "verification_levels": ["unit", "integration", "adversarial"],
  "render": {
    "issue_url_base": "https://github.com/example/project/issues/",
    "source_name": "matrix.json",
    "generator_name": "reqmatrix",
    "regenerate_command": "reqmatrix render -config ... -matrix ... -output ...",
    "check_command": "reqmatrix render -config ... -matrix ... -output ... -check"
  },
  "version_transitions": {
    "require_version_increase_on_change": true,
    "require_review_date_advance_on_change": true,
    "require_major_on_schema_change": true
  }
}
```

## Members

| Member                | Rules                                                                       |
| --------------------- | --------------------------------------------------------------------------- |
| `config_version`      | must be `1`                                                                 |
| `required_standards`  | required array (may be empty); unique standard keys; each key needs a `standard_sources` entry |
| `standard_sources`    | non-empty array; each entry has a unique `key` plus exactly one of `host` or `path` |
| `milestone_pattern`   | anchored regular expression (`^...$`, at most 256 bytes) for `owner.milestone` |
| `issue_pattern`       | anchored regular expression for `owner.issue`                               |
| `risk_pattern`        | anchored regular expression for `traceability.risks` entries                |
| `workstreams`         | non-empty list of allowed `owner.workstream` values                         |
| `verification_levels` | non-empty list of allowed `planned_verification.levels` values (`^[a-z][a-z0-9-]*$`) |
| `render`              | presentation strings; see below                                             |
| `version_transitions` | boolean switches for the `compare` command; see [cli.md](cli.md)            |

### `standard_sources[]`

- `host` — a lowercase multi-label DNS name. Citations and standard URIs for
  this key must be `https://` URIs on exactly this host, with no user
  information, port, or query.
- `path` — an exact relative path (no scheme, backslash, whitespace, or
  leading `/`). Citations for this key must use exactly this path, with an
  optional fragment. Use this for standards defined by a document inside the
  consuming repository; the path is resolved by Markdown viewers relative to
  the rendered file, not by the tool.

### `render`

| Member               | Used for                                                                  |
| -------------------- | ------------------------------------------------------------------------- |
| `issue_url_base`     | HTTPS URL ending in `/`; issue references are appended without their `#`   |
| `source_name`        | the matrix file name shown in the generated header                        |
| `generator_name`     | the generator name shown in the generated header                          |
| `regenerate_command` | shown in the generated footer and in `render -check` failure messages     |
| `check_command`      | shown in the generated footer                                             |

All render strings are single-line and bounded. They are trusted consumer
content: the default template inserts them as inline code or link
destinations without content escaping, so review them like code.

## Templates

The embedded default template produces a status summary, ownership index,
boundary-decision table, per-standard requirement tables, detailed
requirement records, and the supersession ledger.

A consumer template supplied with `render -template` replaces presentation
entirely while keeping validation and data mechanics. It must define a
`matrix` template. It receives:

- `.Document` — the validated matrix document;
- `.Render` — the `render` configuration plus the template path;
- `.ApplicabilityCounts`, `.EvidenceStatusCounts`, `.BoundaryRequirements`,
  `.Ownership`, `.Standards` — the same precomputed sections the default
  template uses; and
- the template functions `htmlText`, `inlineCode`, `inlineValues`,
  `issueURL`, `join`, `linkDestination`, `linkLabel`, `lower`, `owner`,
  `prose`, and `table`.

Matrix content must always pass through the escaping functions (`htmlText`,
`prose`, `table`, `linkLabel`, `inlineValues`, `linkDestination`); emitting
document fields raw lets matrix authors inject Markdown or HTML into the
rendered output. Section layout and precomputed-section membership may
change in minor releases; pin the tool version to keep byte-identical
output, and re-verify consumer templates when updating.
