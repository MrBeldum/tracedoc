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

### Invisible code points

Two layers keep code points that survive Markdown escaping from changing
how output is interpreted or displayed:

- **Validation** rejects control characters (Unicode category Cc, which
  includes NEL) and the line and paragraph separators (Zl/Zp) in every
  validated string — scalar fields and every free-form list item alike.
  The diagnostic reads `contains a control or line-separator character`.
- **Rendering** additionally neutralizes those code points *and* the
  bidirectional embedding, override, and isolate controls
  (U+202A–U+202E, U+2066–U+2069) in every emission context: prose, table
  cells, inline code, link labels, HTML text, and link destinations
  (percent-encoded there rather than dropped). This is defense in depth
  for the validated classes and the primary defense for bidirectional
  controls.

Bidirectional controls are deliberately **not** rejected at validation:
right-to-left content is legitimate in prose, so the boundary is drawn at
rendering, where reordering would mislead a reader of the generated
document. Other format-category (Cf) code points, such as zero-width
joiners, are permitted in both layers.

## Shared structural conventions

Both schemas share these members and semantics:

| Member             | Rules                                                        |
| ------------------ | ------------------------------------------------------------ |
| `document_type`    | `"requirements"` or `"threat_model"`, fixed per schema       |
| `schema_version`   | the schema version the document conforms to                  |
| `document_version` | Semantic Versioning 2.0.0                                    |
| `last_reviewed`    | RFC 3339 full date (`YYYY-MM-DD`)                            |
| `supersessions`    | required array (may be empty), append-only across accepted revisions: `retired_id` (unique, not active), required `replacement_ids` (all entries active; an explicitly empty array records withdrawal without a successor), non-empty `rationale` |

Stable IDs (requirement and threat IDs) share the format
`^[A-Z][A-Z0-9]*-[0-9]{3}$` and are never renumbered or reused. The threat
model additionally declares several other entity collections, each with its
own reserved prefix within that same format
([schema-threat-model.md](schema-threat-model.md#identifiers)); retiring
one requires a retained supersession — naming its replacements when the
obligation was split, merged, or replaced, or with an empty replacement
list when it was withdrawn outright. Withdrawals are as immutable as any
other ledger entry: later granting a withdrawn ID replacements is a
rejected ledger edit. The `compare` command enforces these
guarantees across revisions for both document types
([cli.md](cli.md#matrix-compare--config-path--baseline-path--candidate-path)).
