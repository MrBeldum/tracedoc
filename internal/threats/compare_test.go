package threats_test

import (
	"strings"
	"testing"

	"github.com/sofired/matrix-service/internal/continuity"
	"github.com/sofired/matrix-service/internal/testsupport"
	"github.com/sofired/matrix-service/internal/threats"
)

func allRules() continuity.TransitionRules {
	return continuity.TransitionRules{
		RequireVersionIncreaseOnChange:   true,
		RequireReviewDateAdvanceOnChange: true,
		RequireMajorOnSchemaChange:       true,
	}
}

func loadCompareFixture(t *testing.T) threats.Document {
	t.Helper()
	doc, err := threats.Load(testsupport.FixturePath(t, "threats.json"))
	if err != nil {
		t.Fatalf("load fixture threat model: %v", err)
	}
	return doc
}

func removeThreat(doc *threats.Document, id string) {
	var kept []threats.Threat
	for _, item := range doc.Threats {
		if item.ID != id {
			kept = append(kept, item)
		}
	}
	doc.Threats = kept
}

func TestCompareAcceptsIdenticalDocuments(t *testing.T) {
	if errs := threats.Compare(loadCompareFixture(t), loadCompareFixture(t), allRules()); len(errs) > 0 {
		t.Fatalf("identical documents rejected:\n%s", errs)
	}
}

func TestCompareAcceptsLegalRetirement(t *testing.T) {
	baseline := loadCompareFixture(t)
	candidate := loadCompareFixture(t)
	var kept []threats.Threat
	for _, item := range candidate.Threats {
		if item.ID != "THRT-003" {
			kept = append(kept, item)
		}
	}
	candidate.Threats = kept
	candidate.Supersessions = append(candidate.Supersessions, threats.Supersession{
		RetiredID:      "THRT-003",
		ReplacementIDs: []string{"THRT-001"},
		Rationale:      "Folded downgrade handling into the replay threat.",
	})
	candidate.DocumentVersion = "0.2.0"
	candidate.LastReviewed = "2026-08-01"
	if errs := threats.Compare(baseline, candidate, allRules()); len(errs) > 0 {
		t.Fatalf("legal retirement rejected:\n%s", errs)
	}
}

func TestCompareRejections(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		rules  continuity.TransitionRules
		mutate func(*threats.Document)
	}{
		{
			name:  "deleted threat",
			want:  `threat "THRT-003" was removed without a retained supersession`,
			rules: allRules(),
			mutate: func(doc *threats.Document) {
				var kept []threats.Threat
				for _, item := range doc.Threats {
					if item.ID != "THRT-003" {
						kept = append(kept, item)
					}
				}
				doc.Threats = kept
				doc.DocumentVersion = "0.2.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "reused retired threat ID",
			want:  `retired threat ID "THRT-900" was reused as an active threat`,
			rules: allRules(),
			mutate: func(doc *threats.Document) {
				revived := doc.Threats[0]
				revived.ID = "THRT-900"
				doc.Threats = append(doc.Threats, revived)
				doc.Supersessions = []threats.Supersession{}
				doc.DocumentVersion = "0.2.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "dropped supersession",
			want:  `supersession for retired ID "THRT-900" was dropped`,
			rules: allRules(),
			mutate: func(doc *threats.Document) {
				doc.Supersessions = []threats.Supersession{}
				doc.DocumentVersion = "0.2.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "changed replacement IDs",
			want:  `replacement IDs for retired ID "THRT-900" changed`,
			rules: allRules(),
			mutate: func(doc *threats.Document) {
				doc.Supersessions[0].ReplacementIDs = []string{"THRT-002"}
				doc.DocumentVersion = "0.2.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "version decrease",
			want:  `document_version "0.0.9" is lower than baseline "0.1.0"`,
			rules: continuity.TransitionRules{},
			mutate: func(doc *threats.Document) {
				doc.DocumentVersion = "0.0.9"
			},
		},
		{
			name:  "change without version increase",
			want:  `document changed but document_version "0.1.0" does not increase baseline "0.1.0"`,
			rules: allRules(),
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Title = "Credential replay against the token endpoint"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name:  "review date regression",
			want:  `document changed but last_reviewed "2026-07-01" is earlier than baseline "2026-07-31"`,
			rules: allRules(),
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Title = "Credential replay against the token endpoint"
				doc.DocumentVersion = "0.2.0"
				doc.LastReviewed = "2026-07-01"
			},
		},
		{
			name:  "schema change without major increase",
			want:  "schema_version changed from 1 to 2 without a major document_version increase",
			rules: allRules(),
			mutate: func(doc *threats.Document) {
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
			errs := threats.Compare(baseline, candidate, test.rules)
			if !strings.Contains(errs.Error(), test.want) {
				t.Fatalf("expected %q, got:\n%s", test.want, errs)
			}
		})
	}
}

// TestCompareAcceptsWithdrawal is the threats-package counterpart to
// matrix's TestCompareAcceptsWithdrawal: a supersession with an explicitly
// empty replacement set records a withdrawal, and that withdrawal is as
// immutable as any other supersession entry — a later revision cannot
// retroactively grant it replacements.
func TestCompareAcceptsWithdrawal(t *testing.T) {
	baseline := loadCompareFixture(t)
	candidate := loadCompareFixture(t)
	removeThreat(&candidate, "THRT-003")
	candidate.Supersessions = append(candidate.Supersessions, threats.Supersession{
		RetiredID:      "THRT-003",
		ReplacementIDs: []string{},
		Rationale:      "Metadata downgrade threat withdrawn after the endpoint moved to HTTPS-only.",
	})
	candidate.DocumentVersion = "0.2.0"
	candidate.LastReviewed = "2026-08-01"
	if errs := threats.Compare(baseline, candidate, allRules()); len(errs) > 0 {
		t.Fatalf("withdrawal without successor rejected:\n%s", errs)
	}

	next := loadCompareFixture(t)
	removeThreat(&next, "THRT-003")
	next.Supersessions = append(next.Supersessions, threats.Supersession{
		RetiredID:      "THRT-003",
		ReplacementIDs: []string{"THRT-001"},
		Rationale:      "Metadata downgrade threat withdrawn after the endpoint moved to HTTPS-only.",
	})
	next.DocumentVersion = "0.3.0"
	next.LastReviewed = "2026-08-02"
	errs := threats.Compare(candidate, next, allRules())
	if !strings.Contains(errs.Error(), `replacement IDs for retired ID "THRT-003" changed`) {
		t.Fatalf("expected withdrawal mutation to be rejected, got:\n%s", errs)
	}
}

func TestCompareReplacementSetSemantics(t *testing.T) {
	multiReplacement := func(doc *threats.Document) {
		doc.Supersessions[0].ReplacementIDs = []string{"THRT-001", "THRT-002"}
	}

	t.Run("reordered replacements are retained", func(t *testing.T) {
		baseline := loadCompareFixture(t)
		candidate := loadCompareFixture(t)
		multiReplacement(&baseline)
		candidate.Supersessions[0].ReplacementIDs = []string{"THRT-002", "THRT-001"}
		candidate.DocumentVersion = "0.2.0"
		candidate.LastReviewed = "2026-08-01"
		if errs := threats.Compare(baseline, candidate, allRules()); len(errs) > 0 {
			t.Fatalf("reordered replacement set rejected:\n%s", errs)
		}
	})

	t.Run("dropped replacement is a change", func(t *testing.T) {
		baseline := loadCompareFixture(t)
		candidate := loadCompareFixture(t)
		multiReplacement(&baseline)
		candidate.Supersessions[0].ReplacementIDs = []string{"THRT-001"}
		candidate.DocumentVersion = "0.2.0"
		candidate.LastReviewed = "2026-08-01"
		errs := threats.Compare(baseline, candidate, allRules())
		if !strings.Contains(errs.Error(), `replacement IDs for retired ID "THRT-900" changed`) {
			t.Fatalf("expected dropped replacement to be rejected, got:\n%s", errs)
		}
	})

	t.Run("added replacement is a change", func(t *testing.T) {
		baseline := loadCompareFixture(t)
		candidate := loadCompareFixture(t)
		candidate.Supersessions[0].ReplacementIDs = []string{"THRT-001", "THRT-002"}
		candidate.DocumentVersion = "0.2.0"
		candidate.LastReviewed = "2026-08-01"
		errs := threats.Compare(baseline, candidate, allRules())
		if !strings.Contains(errs.Error(), `replacement IDs for retired ID "THRT-900" changed`) {
			t.Fatalf("expected added replacement to be rejected, got:\n%s", errs)
		}
	})
}

func TestCompareAccumulatesViolations(t *testing.T) {
	baseline := loadCompareFixture(t)
	candidate := loadCompareFixture(t)
	removeThreat(&candidate, "THRT-002")
	candidate.Supersessions[0].ReplacementIDs = []string{"THRT-002", "THRT-003"}
	candidate.DocumentVersion = "0.0.1"
	errs := threats.Compare(baseline, candidate, allRules())
	for _, want := range []string{
		`threat "THRT-002" was removed without a retained supersession`,
		`replacement IDs for retired ID "THRT-900" changed`,
		`document_version "0.0.1" is lower than baseline "0.1.0"`,
	} {
		if !strings.Contains(errs.Error(), want) {
			t.Errorf("expected accumulated violation %q, got:\n%s", want, errs)
		}
	}
}

func TestCompareOptionalRulesCanBeDisabled(t *testing.T) {
	baseline := loadCompareFixture(t)
	candidate := loadCompareFixture(t)
	candidate.Threats[0].Title = "Credential stuffing against the token endpoint, revised"
	candidate.SchemaVersion = 2
	candidate.LastReviewed = "2026-07-01"
	if errs := threats.Compare(baseline, candidate, continuity.TransitionRules{}); len(errs) > 0 {
		t.Fatalf("optional rules were enforced while disabled:\n%s", errs)
	}
}

func TestCompareAllowsSchemaChangeWithMajorIncrease(t *testing.T) {
	baseline := loadCompareFixture(t)
	candidate := loadCompareFixture(t)
	candidate.SchemaVersion = 2
	candidate.DocumentVersion = "1.0.0"
	candidate.LastReviewed = "2026-08-01"
	if errs := threats.Compare(baseline, candidate, allRules()); len(errs) > 0 {
		t.Fatalf("major schema transition rejected:\n%s", errs)
	}
}
