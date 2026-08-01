package matrix_test

import (
	"strings"
	"testing"

	"github.com/sofired/matrix-service/internal/continuity"
	"github.com/sofired/matrix-service/internal/matrix"
	"github.com/sofired/matrix-service/internal/testsupport"
)

func loadCompareFixture(t *testing.T) matrix.Document {
	t.Helper()
	doc, err := matrix.Load(testsupport.FixturePath(t, "matrix.json"))
	if err != nil {
		t.Fatalf("load fixture matrix: %v", err)
	}
	return doc
}

func allRules() continuity.TransitionRules {
	return continuity.TransitionRules{
		RequireVersionIncreaseOnChange:   true,
		RequireReviewDateAdvanceOnChange: true,
		RequireMajorOnSchemaChange:       true,
	}
}

func removeRequirement(doc *matrix.Document, id string) {
	var requirements []matrix.Requirement
	for _, item := range doc.Requirements {
		if item.ID != id {
			requirements = append(requirements, item)
		}
	}
	doc.Requirements = requirements
}

func TestCompareAcceptsIdenticalDocuments(t *testing.T) {
	baseline := loadCompareFixture(t)
	candidate := loadCompareFixture(t)
	if errs := matrix.Compare(baseline, candidate, allRules()); len(errs) > 0 {
		t.Fatalf("identical documents rejected:\n%s", errs)
	}
}

func TestCompareAcceptsLegalRevision(t *testing.T) {
	baseline := loadCompareFixture(t)
	candidate := loadCompareFixture(t)
	removeRequirement(&candidate, "RFCX-001")
	candidate.Requirements = append(candidate.Requirements, matrix.Requirement{ID: "RFCX-002"})
	candidate.Supersessions = append(candidate.Supersessions, matrix.Supersession{
		RetiredID:      "RFCX-001",
		ReplacementIDs: []string{"RFCX-002"},
		Rationale:      "Narrowed to metadata endpoints.",
	})
	candidate.DocumentVersion = "0.3.0"
	candidate.LastReviewed = "2026-08-01"
	if errs := matrix.Compare(baseline, candidate, allRules()); len(errs) > 0 {
		t.Fatalf("legal revision rejected:\n%s", errs)
	}
}

func TestCompareRejections(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		rules  continuity.TransitionRules
		mutate func(*matrix.Document)
	}{
		{
			name:  "deleted requirement",
			want:  `requirement "RFCX-001" was removed without a retained supersession`,
			rules: allRules(),
			mutate: func(doc *matrix.Document) {
				removeRequirement(doc, "RFCX-001")
				doc.DocumentVersion = "0.3.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "reused retired ID",
			want:  `retired requirement ID "EXCORE-900" was reused as an active requirement`,
			rules: allRules(),
			mutate: func(doc *matrix.Document) {
				doc.Requirements = append(doc.Requirements, matrix.Requirement{ID: "EXCORE-900"})
				doc.Supersessions = nil
				doc.DocumentVersion = "0.3.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "dropped supersession",
			want:  `supersession for retired ID "EXCORE-900" was dropped`,
			rules: allRules(),
			mutate: func(doc *matrix.Document) {
				doc.Supersessions = []matrix.Supersession{}
				doc.DocumentVersion = "0.3.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "changed replacement IDs",
			want:  `replacement IDs for retired ID "EXCORE-900" changed`,
			rules: allRules(),
			mutate: func(doc *matrix.Document) {
				doc.Supersessions[0].ReplacementIDs = []string{"RFCX-001"}
				doc.DocumentVersion = "0.3.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "version decrease",
			want:  `document_version "0.1.0" is lower than baseline "0.2.0"`,
			rules: continuity.TransitionRules{},
			mutate: func(doc *matrix.Document) {
				doc.DocumentVersion = "0.1.0"
			},
		},
		{
			name:  "change without version increase",
			want:  `document changed but document_version "0.2.0" does not increase baseline "0.2.0"`,
			rules: allRules(),
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Title = "Reject every unauthenticated token request"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "review date regression",
			want:  `document changed but last_reviewed "2026-07-01" is earlier than baseline "2026-07-30"`,
			rules: allRules(),
			mutate: func(doc *matrix.Document) {
				doc.Requirements[0].Title = "Reject every unauthenticated token request"
				doc.DocumentVersion = "0.3.0"
				doc.LastReviewed = "2026-07-01"
			},
		},
		{
			name:  "schema change without major increase",
			want:  "schema_version changed from 1 to 2 without a major document_version increase",
			rules: allRules(),
			mutate: func(doc *matrix.Document) {
				doc.SchemaVersion = 2
				doc.DocumentVersion = "0.9.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseline := loadCompareFixture(t)
			candidate := loadCompareFixture(t)
			test.mutate(&candidate)
			errs := matrix.Compare(baseline, candidate, test.rules)
			if !strings.Contains(errs.Error(), test.want) {
				t.Fatalf("expected %q, got:\n%s", test.want, errs)
			}
		})
	}
}

func TestCompareReplacementSetSemantics(t *testing.T) {
	multiReplacement := func(doc *matrix.Document) {
		doc.Supersessions[0].ReplacementIDs = []string{"EXCORE-001", "RFCX-001"}
	}

	t.Run("reordered replacements are retained", func(t *testing.T) {
		baseline := loadCompareFixture(t)
		candidate := loadCompareFixture(t)
		multiReplacement(&baseline)
		candidate.Supersessions[0].ReplacementIDs = []string{"RFCX-001", "EXCORE-001"}
		candidate.DocumentVersion = "0.3.0"
		candidate.LastReviewed = "2026-08-01"
		if errs := matrix.Compare(baseline, candidate, allRules()); len(errs) > 0 {
			t.Fatalf("reordered replacement set rejected:\n%s", errs)
		}
	})

	t.Run("dropped replacement is a change", func(t *testing.T) {
		baseline := loadCompareFixture(t)
		candidate := loadCompareFixture(t)
		multiReplacement(&baseline)
		candidate.Supersessions[0].ReplacementIDs = []string{"EXCORE-001"}
		candidate.DocumentVersion = "0.3.0"
		candidate.LastReviewed = "2026-08-01"
		errs := matrix.Compare(baseline, candidate, allRules())
		if !strings.Contains(errs.Error(), `replacement IDs for retired ID "EXCORE-900" changed`) {
			t.Fatalf("expected dropped replacement to be rejected, got:\n%s", errs)
		}
	})

	t.Run("added replacement is a change", func(t *testing.T) {
		baseline := loadCompareFixture(t)
		candidate := loadCompareFixture(t)
		candidate.Supersessions[0].ReplacementIDs = []string{"EXCORE-001", "RFCX-001"}
		candidate.DocumentVersion = "0.3.0"
		candidate.LastReviewed = "2026-08-01"
		errs := matrix.Compare(baseline, candidate, allRules())
		if !strings.Contains(errs.Error(), `replacement IDs for retired ID "EXCORE-900" changed`) {
			t.Fatalf("expected added replacement to be rejected, got:\n%s", errs)
		}
	})
}

func TestCompareAccumulatesViolations(t *testing.T) {
	baseline := loadCompareFixture(t)
	candidate := loadCompareFixture(t)
	removeRequirement(&candidate, "RFCX-001")
	candidate.Supersessions[0].ReplacementIDs = []string{"EXCORE-001", "PLAN-001"}
	candidate.DocumentVersion = "0.1.0"
	errs := matrix.Compare(baseline, candidate, allRules())
	for _, want := range []string{
		`requirement "RFCX-001" was removed without a retained supersession`,
		`replacement IDs for retired ID "EXCORE-900" changed`,
		`document_version "0.1.0" is lower than baseline "0.2.0"`,
	} {
		if !strings.Contains(errs.Error(), want) {
			t.Errorf("expected accumulated violation %q, got:\n%s", want, errs)
		}
	}
}

func TestCompareOptionalRulesCanBeDisabled(t *testing.T) {
	baseline := loadCompareFixture(t)
	candidate := loadCompareFixture(t)
	candidate.Requirements[0].Title = "Reject every unauthenticated token request"
	candidate.SchemaVersion = 2
	candidate.LastReviewed = "2026-07-01"
	if errs := matrix.Compare(baseline, candidate, continuity.TransitionRules{}); len(errs) > 0 {
		t.Fatalf("optional rules were enforced while disabled:\n%s", errs)
	}
}

func TestCompareAllowsSchemaChangeWithMajorIncrease(t *testing.T) {
	baseline := loadCompareFixture(t)
	candidate := loadCompareFixture(t)
	candidate.SchemaVersion = 2
	candidate.DocumentVersion = "1.0.0"
	candidate.LastReviewed = "2026-08-01"
	if errs := matrix.Compare(baseline, candidate, allRules()); len(errs) > 0 {
		t.Fatalf("major schema transition rejected:\n%s", errs)
	}
}
