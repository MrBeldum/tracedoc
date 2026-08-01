package matrix

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func loadCompareFixture(t *testing.T) Document {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	path := filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "matrix.json")
	doc, err := Load(path)
	if err != nil {
		t.Fatalf("load fixture matrix: %v", err)
	}
	return doc
}

func allRules() TransitionRules {
	return TransitionRules{
		RequireVersionIncreaseOnChange:   true,
		RequireReviewDateAdvanceOnChange: true,
		RequireMajorOnSchemaChange:       true,
	}
}

func removeRequirement(doc *Document, id string) {
	var requirements []Requirement
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
	if errs := Compare(baseline, candidate, allRules()); len(errs) > 0 {
		t.Fatalf("identical documents rejected:\n%s", errs)
	}
}

func TestCompareAcceptsLegalRevision(t *testing.T) {
	baseline := loadCompareFixture(t)
	candidate := loadCompareFixture(t)
	removeRequirement(&candidate, "RFCX-001")
	candidate.Requirements = append(candidate.Requirements, Requirement{ID: "RFCX-002"})
	candidate.Supersessions = append(candidate.Supersessions, Supersession{
		RetiredID:      "RFCX-001",
		ReplacementIDs: []string{"RFCX-002"},
		Rationale:      "Narrowed to metadata endpoints.",
	})
	candidate.MatrixVersion = "0.3.0"
	candidate.LastReviewed = "2026-08-01"
	if errs := Compare(baseline, candidate, allRules()); len(errs) > 0 {
		t.Fatalf("legal revision rejected:\n%s", errs)
	}
}

func TestCompareRejections(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		rules  TransitionRules
		mutate func(*Document)
	}{
		{
			name:  "deleted requirement",
			want:  `requirement "RFCX-001" was removed without a retained supersession`,
			rules: allRules(),
			mutate: func(doc *Document) {
				removeRequirement(doc, "RFCX-001")
				doc.MatrixVersion = "0.3.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "reused retired ID",
			want:  `retired requirement ID "EXCORE-900" was reused as an active requirement`,
			rules: allRules(),
			mutate: func(doc *Document) {
				doc.Requirements = append(doc.Requirements, Requirement{ID: "EXCORE-900"})
				doc.Supersessions = nil
				doc.MatrixVersion = "0.3.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "dropped supersession",
			want:  `supersession for retired ID "EXCORE-900" was dropped`,
			rules: allRules(),
			mutate: func(doc *Document) {
				doc.Supersessions = []Supersession{}
				doc.MatrixVersion = "0.3.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "changed replacement IDs",
			want:  `replacement IDs for retired ID "EXCORE-900" changed`,
			rules: allRules(),
			mutate: func(doc *Document) {
				doc.Supersessions[0].ReplacementIDs = []string{"RFCX-001"}
				doc.MatrixVersion = "0.3.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "version decrease",
			want:  `matrix_version "0.1.0" is lower than baseline "0.2.0"`,
			rules: TransitionRules{},
			mutate: func(doc *Document) {
				doc.MatrixVersion = "0.1.0"
			},
		},
		{
			name:  "change without version increase",
			want:  `matrix changed but matrix_version "0.2.0" does not increase baseline "0.2.0"`,
			rules: allRules(),
			mutate: func(doc *Document) {
				doc.Requirements[0].Title = "Reject every unauthenticated token request"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "review date regression",
			want:  `matrix changed but last_reviewed "2026-07-01" is earlier than baseline "2026-07-30"`,
			rules: allRules(),
			mutate: func(doc *Document) {
				doc.Requirements[0].Title = "Reject every unauthenticated token request"
				doc.MatrixVersion = "0.3.0"
				doc.LastReviewed = "2026-07-01"
			},
		},
		{
			name:  "schema change without major increase",
			want:  "schema_version changed from 1 to 2 without a major matrix_version increase",
			rules: allRules(),
			mutate: func(doc *Document) {
				doc.SchemaVersion = 2
				doc.MatrixVersion = "0.9.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseline := loadCompareFixture(t)
			candidate := loadCompareFixture(t)
			test.mutate(&candidate)
			errs := Compare(baseline, candidate, test.rules)
			if !strings.Contains(errs.Error(), test.want) {
				t.Fatalf("expected %q, got:\n%s", test.want, errs)
			}
		})
	}
}

func TestCompareReplacementSetSemantics(t *testing.T) {
	multiReplacement := func(doc *Document) {
		doc.Supersessions[0].ReplacementIDs = []string{"EXCORE-001", "RFCX-001"}
	}

	t.Run("reordered replacements are retained", func(t *testing.T) {
		baseline := loadCompareFixture(t)
		candidate := loadCompareFixture(t)
		multiReplacement(&baseline)
		candidate.Supersessions[0].ReplacementIDs = []string{"RFCX-001", "EXCORE-001"}
		candidate.MatrixVersion = "0.3.0"
		candidate.LastReviewed = "2026-08-01"
		if errs := Compare(baseline, candidate, allRules()); len(errs) > 0 {
			t.Fatalf("reordered replacement set rejected:\n%s", errs)
		}
	})

	t.Run("dropped replacement is a change", func(t *testing.T) {
		baseline := loadCompareFixture(t)
		candidate := loadCompareFixture(t)
		multiReplacement(&baseline)
		candidate.Supersessions[0].ReplacementIDs = []string{"EXCORE-001"}
		candidate.MatrixVersion = "0.3.0"
		candidate.LastReviewed = "2026-08-01"
		errs := Compare(baseline, candidate, allRules())
		if !strings.Contains(errs.Error(), `replacement IDs for retired ID "EXCORE-900" changed`) {
			t.Fatalf("expected dropped replacement to be rejected, got:\n%s", errs)
		}
	})

	t.Run("added replacement is a change", func(t *testing.T) {
		baseline := loadCompareFixture(t)
		candidate := loadCompareFixture(t)
		candidate.Supersessions[0].ReplacementIDs = []string{"EXCORE-001", "RFCX-001"}
		candidate.MatrixVersion = "0.3.0"
		candidate.LastReviewed = "2026-08-01"
		errs := Compare(baseline, candidate, allRules())
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
	candidate.MatrixVersion = "0.1.0"
	errs := Compare(baseline, candidate, allRules())
	for _, want := range []string{
		`requirement "RFCX-001" was removed without a retained supersession`,
		`replacement IDs for retired ID "EXCORE-900" changed`,
		`matrix_version "0.1.0" is lower than baseline "0.2.0"`,
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
	if errs := Compare(baseline, candidate, TransitionRules{}); len(errs) > 0 {
		t.Fatalf("optional rules were enforced while disabled:\n%s", errs)
	}
}

func TestCompareAllowsSchemaChangeWithMajorIncrease(t *testing.T) {
	baseline := loadCompareFixture(t)
	candidate := loadCompareFixture(t)
	candidate.SchemaVersion = 2
	candidate.MatrixVersion = "1.0.0"
	candidate.LastReviewed = "2026-08-01"
	if errs := Compare(baseline, candidate, allRules()); len(errs) > 0 {
		t.Fatalf("major schema transition rejected:\n%s", errs)
	}
}
