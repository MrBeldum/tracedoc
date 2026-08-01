package matrix_test

import (
	"strings"
	"testing"

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
	return config.MatrixPolicy()
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

	tests := []struct {
		name   string
		want   string
		mutate func(*matrix.Document)
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
				doc.MatrixVersion = "1.0.0-01"
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
			name: "unknown citation standard",
			want: `unknown standard "UNKNOWN"`,
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
				doc.Requirements[0].Title = strings.Repeat("x", matrix.MaxStringBytes+1)
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
					strings.Repeat("x", matrix.MaxStringBytes+1)
			},
		},
		{
			name: "oversized rationale on applicable item",
			want: "applicability_rationale: exceeds 16384-byte limit",
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].ApplicabilityRationale =
					strings.Repeat("x", matrix.MaxStringBytes+1)
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
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doc := fixtureDocument(t)
			test.mutate(&doc)
			if errs := matrix.Validate(doc, pol); !strings.Contains(errs.Error(), test.want) {
				t.Fatalf("expected %q, got:\n%s", test.want, errs)
			}
		})
	}
}
