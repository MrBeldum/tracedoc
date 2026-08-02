# Consumer configuration, version 1

The configuration file carries every project-specific rule the tool
applies: shared settings at the top level plus one optional section per
document type. It is a bounded set of declarative knobs, deliberately not
a general-purpose validation language: new kinds of rules require a tool
change and a configuration schema revision, not cleverer configuration.

The file obeys the same lexical contract as the documents (strict
decoding, canonical member names, unknown members rejected) with a 1 MiB
size limit.

Example:

```json
{
  "config_version": 1,
  "milestone_pattern": "^M(?:[0-9]|1[01])$",
  "issue_pattern": "^#[1-9][0-9]*$",
  "risk_pattern": "^R(?:[1-9]|1[0-2])$",
  "workstreams": ["Protocol", "Platform"],
  "issue_url_base": "https://github.com/example/project/issues/",
  "generator_name": "matrix",
  "version_transitions": {
    "require_version_increase_on_change": true,
    "require_review_date_advance_on_change": true,
    "require_major_on_schema_change": true
  },
  "requirements": {
    "required_standards": ["EXAMPLE-CORE", "LOCAL-PLAN"],
    "standard_sources": [
      { "key": "EXAMPLE-CORE", "host": "standards.example.org" },
      { "key": "LOCAL-PLAN", "path": "../plan.md" }
    ],
    "verification_levels": ["unit", "integration", "adversarial"],
    "render": {
      "source_name": "matrix.json",
      "regenerate_command": "matrix render -config ... -doc matrix.json -output matrix.md",
      "check_command": "matrix render -config ... -doc matrix.json -output matrix.md -check"
    }
  },
  "threat_model": {
    "render": {
      "source_name": "threats.json",
      "regenerate_command": "matrix render -config ... -doc threats.json -output threats.md",
      "check_command": "matrix render -config ... -doc threats.json -output threats.md -check"
    }
  }
}
```

## Shared top-level members

These describe the project — its work tracking, risk register, and issue
tracker — and apply identically to every document type:

| Member                | Rules                                                                        |
| --------------------- | ---------------------------------------------------------------------------- |
| `config_version`      | must be `1`                                                                  |
| `milestone_pattern`   | anchored regular expression (`^...$`, at most 256 bytes) for `owner.milestone` |
| `issue_pattern`       | anchored regular expression for `owner.issue`                                |
| `risk_pattern`        | anchored regular expression for risk-record identifiers                      |
| `workstreams`         | non-empty list of allowed `owner.workstream` values                          |
| `issue_url_base`      | HTTPS URL ending in `/`; issue references are appended without their `#`     |
| `generator_name`      | generator name shown in generated headers                                    |
| `version_transitions` | boolean switches for the `compare` command; see [cli.md](cli.md), including the reachability caveat on `require_major_on_schema_change` |

## Per-document-type sections

Sections are optional; running a command against a document whose type has
no section is exit `2`.

### `requirements`

| Member                | Rules                                                                       |
| --------------------- | --------------------------------------------------------------------------- |
| `required_standards`  | required array (may be empty); unique standard keys; each key needs a `standard_sources` entry |
| `standard_sources`    | non-empty array; each entry has a unique `key` plus exactly one of `host` or `path` |
| `verification_levels` | non-empty list of allowed `planned_verification.levels` values (`^[a-z][a-z0-9-]*$`) |
| `render`              | presentation strings; see below                                             |

`standard_sources[]`:

- `host` — a lowercase multi-label DNS name. Citations and standard URIs for
  this key must be `https://` URIs on exactly this host, with no user
  information, port, or query.
- `path` — an exact relative path (no scheme, backslash, whitespace, or
  leading `/`). Citations for this key must use exactly this path, with an
  optional fragment. Use this for standards defined by a document inside the
  consuming repository; the path is resolved by Markdown viewers relative to
  the rendered file, not by the tool.

### `threat_model`

| Member   | Rules                              |
| -------- | ---------------------------------- |
| `render` | presentation strings; see below    |

The severity and disposition vocabularies and the asset/boundary/threat ID
formats are schema-owned
([schema-threat-model.md](schema-threat-model.md)), so the section
currently holds only presentation strings; future threat-specific knobs
get a home here.

### `render` (per section)

| Member               | Used for                                                                  |
| -------------------- | ------------------------------------------------------------------------- |
| `source_name`        | the source file name shown in the generated header                        |
| `regenerate_command` | shown in the generated footer and in `render -check` failure messages     |
| `check_command`      | shown in the generated footer                                             |

All render strings are single-line and bounded. Together with the shared
`issue_url_base` and `generator_name`, they are trusted consumer content:
the default templates insert them as inline code or link destinations
without content escaping, so review them like code.

## Templates

Each document type has an embedded default template. A consumer template
supplied with `render -template` replaces presentation entirely while
keeping validation and data mechanics. It must define a `document`
template, and the template file is limited to 1 MiB. It receives:

- `.Document` — the validated document;
- `.Render` — the resolved presentation options;
- the document type's precomputed sections — for requirements:
  `.ApplicabilityCounts`, `.EvidenceStatusCounts`, `.BoundaryRequirements`,
  `.Ownership`, `.Standards`; for threat models: `.SeverityCounts`,
  `.DispositionCounts`, `.Assets`, `.Boundaries`, `.SeveritySections`; and
- the template functions `htmlText`, `inlineCode`, `inlineValues`,
  `issueURL`, `join`, `linkDestination`, `linkLabel`, `lower`, `owner`,
  `prose`, and `table`.

Free-text document fields must always pass through the escaping functions
(`htmlText`, `prose`, `table`, `linkLabel`, `inlineValues`,
`linkDestination`, `inlineCode`); emitting document fields raw lets
document authors inject Markdown or HTML into the rendered output. Stable
ID fields (`^[A-Z][A-Z0-9]*-[0-9]{3}$`), standard keys
(`^[A-Z][A-Z0-9]*(?:[-.][A-Z0-9]+)*$`), and the fixed enum vocabularies
(`applicability`, `evidence_status`, `severity`, `disposition`) are
exempt in the default templates and may be emitted bare only because the
schema constrains their character sets to values that cannot carry Markdown
or HTML structure; anything else emitted raw is an injection risk. Section
layout and precomputed-section membership may change in minor releases;
pin the tool version to keep byte-identical output, and re-verify consumer
templates when updating. Every escaping function also neutralizes
invisible code points; see
[the shared lexical contract](schema.md#invisible-code-points).
