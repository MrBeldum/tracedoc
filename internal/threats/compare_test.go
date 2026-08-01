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
		mutate func(*threats.Document)
	}{
		{
			name: "deleted threat",
			want: `threat "THRT-003" was removed without a retained supersession`,
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
			name: "reused retired threat ID",
			want: `retired threat ID "THRT-900" was reused as an active threat`,
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
			name: "dropped supersession",
			want: `supersession for retired ID "THRT-900" was dropped`,
			mutate: func(doc *threats.Document) {
				doc.Supersessions = []threats.Supersession{}
				doc.DocumentVersion = "0.2.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name: "changed replacement IDs",
			want: `replacement IDs for retired ID "THRT-900" changed`,
			mutate: func(doc *threats.Document) {
				doc.Supersessions[0].ReplacementIDs = []string{"THRT-002"}
				doc.DocumentVersion = "0.2.0"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name: "change without version increase",
			want: `document changed but document_version "0.1.0" does not increase baseline "0.1.0"`,
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Title = "Credential replay against the token endpoint"
				doc.LastReviewed = "2026-08-01"
			},
		},
		{
			name: "review date regression",
			want: `document changed but last_reviewed "2026-07-01" is earlier than baseline "2026-07-31"`,
			mutate: func(doc *threats.Document) {
				doc.Threats[0].Title = "Credential replay against the token endpoint"
				doc.DocumentVersion = "0.2.0"
				doc.LastReviewed = "2026-07-01"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseline := loadCompareFixture(t)
			candidate := loadCompareFixture(t)
			test.mutate(&candidate)
			errs := threats.Compare(baseline, candidate, allRules())
			if !strings.Contains(errs.Error(), test.want) {
				t.Fatalf("expected %q, got:\n%s", test.want, errs)
			}
		})
	}
}
