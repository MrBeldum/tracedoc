# Document schemas

The tool reads two document types, each with its own independently
versioned schema:

- [schema-requirements.md](schema-requirements.md) — the requirements
  matrix (`"document_type": "requirements"`), schema version 1.
- [schema-threat-model.md](schema-threat-model.md) — the system threat
  model (`"document_type": "threat_model"`), schema version 1.

Schema changes follow the policy in [versioning.md](versioning.md).

## Shared lexical contract

Every document, regardless of type, must satisfy before structural
validation:

- at most 8 MiB;
- nesting depth at most 16;
- object member names match `^[a-z][a-z0-9_]*$`;
- no duplicate member names within an object;
- no members outside the document's schema;
- exactly one top-level JSON value; and
- a top-level `document_type` member naming the schema family.

Every validated string field is limited to 16 KiB. All string fields are
plain text: authored Markdown and HTML are not supported, and the renderer
escapes content so it cannot introduce Markdown structure or raw HTML.
Formatted content requires a future, explicitly named field and a separate
validation contract.

## Shared structural conventions

Both schemas share these members and semantics:

| Member             | Rules                                                        |
| ------------------ | ------------------------------------------------------------ |
| `document_type`    | `"requirements"` or `"threat_model"`, fixed per schema       |
| `schema_version`   | the schema version the document conforms to                  |
| `document_version` | Semantic Versioning 2.0.0                                    |
| `last_reviewed`    | RFC 3339 full date (`YYYY-MM-DD`)                            |
| `supersessions`    | required array (may be empty), append-only across accepted revisions: `retired_id` (unique, not active), non-empty `replacement_ids` (all active), non-empty `rationale` |

Stable IDs (requirement and threat IDs) share the format
`^[A-Z][A-Z0-9]*-[0-9]{3}$` and are never renumbered or reused; retiring
one requires a retained supersession. The `compare` command enforces these
guarantees across revisions for both document types
([cli.md](cli.md#matrix-compare--config-path--baseline-path--candidate-path)).
