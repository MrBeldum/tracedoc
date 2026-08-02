package matrix_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/sofired/matrix-service/internal/check"
	"github.com/sofired/matrix-service/internal/matrix"
	"github.com/sofired/matrix-service/internal/policy"
	"github.com/sofired/matrix-service/internal/testsupport"
)

func fixturePolicy(t *testing.T) matrix.Policy {
	t.Helper()
	config, err := policy.Load(testsupport.FixturePath(t, "config.json"))
	if err != nil {
		t.Fatalf("load fixture config: %v", err)
	}
	pol, err := config.RequirementsPolicy()
	if err != nil {
		t.Fatalf("compile requirements policy: %v", err)
	}
	return pol
}

func fixtureDocument(t *testing.T) matrix.Document {
	t.Helper()
	doc, err := matrix.Load(testsupport.FixturePath(t, "matrix.json"))
	if err != nil {
		t.Fatalf("load fixture matrix: %v", err)
	}
	return doc
}

func requirementByID(t *testing.T, doc *matrix.Document, id string) *matrix.Requirement {
	t.Helper()
	for index := range doc.Requirements {
		if doc.Requirements[index].ID == id {
			return &doc.Requirements[index]
		}
	}
	t.Fatalf("requirement %s not found", id)
	return nil
}

func TestMatrixValidation(t *testing.T) {
	pol := fixturePolicy(t)
	if errs := matrix.Validate(fixtureDocument(t), pol); len(errs) > 0 {
		t.Fatalf("fixture matrix is invalid:\n%s", errs)
	}

	// A withdrawal — a supersession with an explicitly empty replacement
	// set — is a legal ledger entry.
	withdrawal := fixtureDocument(t)
	withdrawal.Supersessions = append(withdrawal.Supersessions, matrix.Supersession{
		RetiredID:      "EXCORE-901",
		ReplacementIDs: []string{},
		Rationale:      "Obligation withdrawn after the upstream draft was abandoned.",
	})
	if errs := matrix.Validate(withdrawal, pol); len(errs) > 0 {
		t.Fatalf("withdrawal supersession rejected:\n%s", errs)
	}

	tests := []struct {
		name    string
		want    string
		notWant string
		mutate  func(*matrix.Document)
	}{
		{
			name: "duplicate requirement ID",
			want: "duplicate requirement ID",
			mutate: func(doc *matrix.Document) {
				doc.Requirements = append(doc.Requirements, doc.Requirements[0])
			},
		},
		{
			name: "missing citation",
			want: "expected at least one citation",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Citations = nil
			},
		},
		{
			name: "missing primary standard citation",
			want: `expected at least one citation for primary standard "EXAMPLE-CORE"`,
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Citations = doc.Requirements[0].Citations[1:2]
			},
		},
		{
			name: "missing required standard",
			want: `required standard "RFCX" is missing`,
			mutate: func(doc *matrix.Document) {
				doc.Standards = append(doc.Standards[:1], doc.Standards[2:]...)
			},
		},
		{
			name: "unsafe standard key",
			want: "expected a stable standard key",
			mutate: func(doc *matrix.Document) {
				doc.Standards[0].Key = "example-core"
			},
		},
		{
			name: "unsupported evidence status",
			want: `unsupported value "unknown"`,
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].EvidenceStatus = "unknown"
			},
		},
		{
			name: "missing owner",
			want: "owner: expected an object",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Owner = nil
			},
		},
		{
			name: "missing planned verification",
			want: "planned_verification: expected an object",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].PlannedVerification = nil
			},
		},
		{
			name: "wrong document type",
			want: `document_type: expected "requirements"`,
			mutate: func(doc *matrix.Document) {
				doc.DocumentType = "threat_model"
			},
		},
		{
			name: "unsupported schema version",
			want: "schema_version: expected 1",
			mutate: func(doc *matrix.Document) {
				doc.SchemaVersion = 2
			},
		},
		{
			name: "malformed matrix version",
			want: "expected a semantic version",
			mutate: func(doc *matrix.Document) {
				doc.DocumentVersion = "1.0.0-01"
			},
		},
		{
			name: "invalid review date",
			want: "expected an RFC 3339 full date",
			mutate: func(doc *matrix.Document) {
				doc.LastReviewed = "2026-02-30"
			},
		},
		{
			name: "unsafe standard source URI",
			want: "expected an HTTPS URI",
			mutate: func(doc *matrix.Document) {
				doc.Standards[0].URI = "http://standards.example.org/core/1.0"
			},
		},
		{
			name: "citation on wrong source host",
			want: "expected an HTTPS URI on standards.example.org",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Citations[0].URI =
					"https://www.rfc-editor.org/rfc/rfc9999"
			},
		},
		{
			name: "local source traversal",
			want: "LOCAL-PLAN URI must reference ../plan.md",
			mutate: func(doc *matrix.Document) {
				requirementByID(t, doc, "PLAN-001").Citations[0].URI = "../../README.md"
			},
		},
		{
			name: "standard without URI policy",
			want: `no URI policy for standard "NEWSTD"`,
			mutate: func(doc *matrix.Document) {
				doc.Standards = append(doc.Standards, matrix.Standard{
					Key:   "NEWSTD",
					Title: "Unknown source",
					URI:   "https://standards.example.org/new",
				})
			},
		},
		{
			name: "missing deferred rationale",
			want: "required for deferred",
			mutate: func(doc *matrix.Document) {
				requirementByID(t, doc, "EXCORE-002").ApplicabilityRationale = ""
			},
		},
		{
			name: "incompatible applicability status",
			want: "applicable item has incompatible status",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].EvidenceStatus = "deferred"
			},
		},
		{
			name: "nil traceability array",
			want: "traceability.adrs: expected an array",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Traceability.ADRs = nil
			},
		},
		{
			name: "opaque citation URI",
			want: "opaque URIs, user information, ports, and queries are not allowed",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Citations[0].URI = "mailto:evil@example.org"
			},
		},
		{
			name: "unparseable citation URI",
			want: "invalid URI",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Citations[0].URI = "https://standards.example.org/%zz"
			},
		},
		{
			name: "citation URI with an encoded control character",
			want: "contains encoded whitespace or a control character",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Citations[0].URI = "https://standards.example.org/a%0Ab"
			},
		},
		{
			name: "unknown citation standard with malformed URI keeps lexical check",
			want: "contains whitespace, a control character, or a backslash",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Citations[0].Standard = "UNKNOWN"
				doc.Requirements[0].Citations[0].URI = "https://evil.example/a b"
			},
		},
		{
			name: "unknown citation standard",
			want: `unknown standard "UNKNOWN"`,
			// An unknown standard has no URI policy to check the citation
			// URI against; that must not cascade into a second, redundant
			// "no URI policy" diagnostic for the same citation.
			notWant: "no URI policy",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Citations[0].Standard = "UNKNOWN"
			},
		},
		{
			name: "uncovered declared standard",
			want: `"RFCX" has no requirement`,
			mutate: func(doc *matrix.Document) {
				var requirements []matrix.Requirement
				for _, item := range doc.Requirements {
					if item.Standard != "RFCX" {
						requirements = append(requirements, item)
					}
				}
				doc.Requirements = requirements
			},
		},
		{
			name: "invalid milestone",
			want: "owner.milestone: invalid milestone",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Owner.Milestone = "M12"
			},
		},
		{
			name: "unsafe issue reference",
			want: "owner.issue: invalid issue reference",
			mutate: func(doc *matrix.Document) {
				issue := `#36"><script>alert(1)</script>`
				doc.Requirements[0].Owner.Issue = &issue
			},
		},
		{
			name: "unknown workstream",
			want: "owner.workstream: unknown workstream",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Owner.Workstream = "Unknown"
			},
		},
		{
			name: "invalid risk",
			want: `invalid risk "R13"`,
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Traceability.Risks = []string{"R13"}
			},
		},
		{
			name: "missing replacement array",
			want: "replacement_ids: expected an array",
			mutate: func(doc *matrix.Document) {
				doc.Supersessions[0].ReplacementIDs = nil
			},
		},
		{
			name: "unknown supersession replacement",
			want: `unknown active ID "UNKNOWN-001"`,
			mutate: func(doc *matrix.Document) {
				doc.Supersessions = append(doc.Supersessions, matrix.Supersession{
					RetiredID:      "OLD-001",
					ReplacementIDs: []string{"UNKNOWN-001"},
					Rationale:      "Replacement test.",
				})
			},
		},
		{
			name: "retired ID still active",
			want: "retired ID is still active",
			mutate: func(doc *matrix.Document) {
				doc.Supersessions[0].RetiredID = "RFCX-001"
			},
		},
		{
			name: "duplicate list value",
			want: `duplicate value "unit"`,
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].PlannedVerification.Levels = []string{"unit", "unit"}
			},
		},
		{
			name: "unsupported verification level",
			want: `unsupported values ["fuzzing"]`,
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].PlannedVerification.Levels = []string{"fuzzing"}
			},
		},
		{
			name: "duplicate citation",
			want: "duplicate citation",
			mutate: func(doc *matrix.Document) {
				item := &doc.Requirements[0]
				item.Citations = append(item.Citations, item.Citations[0])
			},
		},
		{
			name: "oversized string",
			want: "exceeds 16384-byte limit",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Title = strings.Repeat("x", check.MaxStringBytes+1)
			},
		},
		{
			name: "unsupported applicability",
			want: `applicability: unsupported value "optional"`,
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Applicability = "optional"
			},
		},
		{
			name: "oversized applicability rationale",
			want: "applicability_rationale: exceeds 16384-byte limit",
			mutate: func(doc *matrix.Document) {
				requirementByID(t, doc, "EXCORE-002").ApplicabilityRationale =
					strings.Repeat("x", check.MaxStringBytes+1)
			},
		},
		{
			name: "oversized rationale on applicable item",
			want: "applicability_rationale: exceeds 16384-byte limit",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].ApplicabilityRationale =
					strings.Repeat("x", check.MaxStringBytes+1)
			},
		},
		{
			name: "duplicate retired ID",
			want: `duplicate retired ID "EXCORE-900"`,
			mutate: func(doc *matrix.Document) {
				doc.Supersessions = append(doc.Supersessions, matrix.Supersession{
					RetiredID:      "EXCORE-900",
					ReplacementIDs: []string{"RFCX-001"},
					Rationale:      "Duplicate ledger entry.",
				})
			},
		},
		{
			name: "blank title",
			want: "requirements[0].title: expected a non-empty string",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Title = ""
			},
		},
		{
			name: "blank evidence item",
			want: "planned_verification.evidence[0]: expected a non-empty string",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].PlannedVerification.Evidence = []string{""}
			},
		},
		{
			name: "empty standards array",
			want: "standards: expected a non-empty array",
			mutate: func(doc *matrix.Document) {
				doc.Standards = []matrix.Standard{}
			},
		},
		{
			name: "empty requirements array",
			want: "requirements: expected a non-empty array",
			mutate: func(doc *matrix.Document) {
				doc.Requirements = []matrix.Requirement{}
			},
		},
		{
			name: "nil supersessions",
			want: "supersessions: expected an array",
			mutate: func(doc *matrix.Document) {
				doc.Supersessions = nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doc := fixtureDocument(t)
			test.mutate(&doc)
			errs := matrix.Validate(doc, pol)
			if !strings.Contains(errs.Error(), test.want) {
				t.Fatalf("expected %q, got:\n%s", test.want, errs)
			}
			if test.notWant != "" && strings.Contains(errs.Error(), test.notWant) {
				t.Fatalf("expected error list to not contain %q, got:\n%s", test.notWant, errs)
			}
		})
	}
}

// TestOwnerMilestoneAndIssueAreBoundedAndControlCharacterFree is the
// security-regression coverage for Owner.Milestone and Owner.Issue: before
// this fix they were validated solely by the consumer-supplied pattern, so
// a permissive pattern let an oversized or control-character-bearing value
// straight through, in violation of the documented 16 KiB bound every
// validated string field must observe.
func TestOwnerMilestoneAndIssueAreBoundedAndControlCharacterFree(t *testing.T) {
	pol := fixturePolicy(t)

	t.Run("oversized milestone", func(t *testing.T) {
		doc := fixtureDocument(t)
		doc.Requirements[0].Owner.Milestone = strings.Repeat("M", check.MaxStringBytes+1)
		errs := matrix.Validate(doc, pol)
		if !strings.Contains(errs.Error(), "exceeds 16384-byte limit") {
			t.Fatalf("expected oversized-milestone rejection, got:\n%s", errs)
		}
	})

	t.Run("issue with a control character is rejected even under a permissive pattern", func(t *testing.T) {
		// This is the security-regression test: the pattern below accepts
		// any string, including one carrying a newline, so a value only
		// the length/control-character bound can catch must still be
		// rejected.
		permissive := pol
		permissive.Issue = regexp.MustCompile(`(?s)^.*$`)

		doc := fixtureDocument(t)
		issue := "#36\nmalicious content"
		doc.Requirements[0].Owner.Issue = &issue

		errs := matrix.Validate(doc, permissive)
		if !strings.Contains(errs.Error(), "contains a control or line-separator character") {
			t.Fatalf("expected control-character rejection under a permissive pattern, got:\n%s", errs)
		}
	})

	t.Run("issue with a Unicode line separator is rejected", func(t *testing.T) {
		// U+2028 is category Zl, not Cc, so it needs the explicit
		// line-separator rejection rather than unicode.IsControl.
		permissive := pol
		permissive.Issue = regexp.MustCompile(`(?s)^.*$`)

		doc := fixtureDocument(t)
		issue := "#36\u2028sneaky"
		doc.Requirements[0].Owner.Issue = &issue

		errs := matrix.Validate(doc, permissive)
		if !strings.Contains(errs.Error(), "contains a control or line-separator character") {
			t.Fatalf("expected line-separator rejection, got:\n%s", errs)
		}
	})
}

// TestRiskEntriesAreControlFreeUnderPermissivePattern mirrors the owner
// regression test for the risks list: a consumer Risk pattern is policy,
// not a lexical safety net.
func TestRiskEntriesAreControlFreeUnderPermissivePattern(t *testing.T) {
	permissive := fixturePolicy(t)
	permissive.Risk = regexp.MustCompile(`(?s)^.*$`)

	doc := fixtureDocument(t)
	doc.Requirements[0].Traceability.Risks = []string{"R1\x1b[31mred"}

	errs := matrix.Validate(doc, permissive)
	if !strings.Contains(errs.Error(), "contains a control or line-separator character") {
		t.Fatalf("expected control-character rejection for a risk entry, got:\n%s", errs)
	}
}

// TestApplicabilityNotApplicableValidatesCleanly is positive enum coverage:
// "not-applicable" applicability, paired with a matching "not-applicable"
// evidence_status and a rationale, is a legal in-memory mutation of the
// fixture document, not just a rejection case.
func TestApplicabilityNotApplicableValidatesCleanly(t *testing.T) {
	pol := fixturePolicy(t)
	doc := fixtureDocument(t)
	item := requirementByID(t, &doc, "RFCX-001")
	item.Applicability = "not-applicable"
	item.ApplicabilityRationale = "No longer relevant to the current project scope."
	item.EvidenceStatus = "not-applicable"
	if errs := matrix.Validate(doc, pol); len(errs) > 0 {
		t.Fatalf("not-applicable requirement rejected:\n%s", errs)
	}
}

// TestEvidenceStatusVerifiedValidatesCleanly is positive enum coverage:
// "verified" is a legal evidence_status for an applicable requirement.
func TestEvidenceStatusVerifiedValidatesCleanly(t *testing.T) {
	pol := fixturePolicy(t)
	doc := fixtureDocument(t)
	doc.Requirements[0].EvidenceStatus = "verified"
	if errs := matrix.Validate(doc, pol); len(errs) > 0 {
		t.Fatalf("verified evidence status rejected:\n%s", errs)
	}
}
