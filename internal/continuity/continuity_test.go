package continuity

import (
	"strings"
	"testing"
)

func baseSnapshot() Snapshot {
	return Snapshot{
		SchemaVersion: 1,
		Version:       "1.0.0",
		LastReviewed:  "2026-07-01",
		ActiveIDs:     map[string]struct{}{"X-001": {}, "X-002": {}},
		Supersessions: map[string][]string{"X-900": {"X-001"}},
	}
}

func TestCompareLabelsMessages(t *testing.T) {
	candidate := baseSnapshot()
	candidate.ActiveIDs = map[string]struct{}{"X-001": {}, "X-900": {}}
	candidate.Supersessions = map[string][]string{}
	errs := Compare(baseSnapshot(), candidate, true, TransitionRules{}, Labels{IDNoun: "item"})
	joined := errs.Error()
	for _, want := range []string{
		`item "X-002" was removed without a retained supersession`,
		`retired item ID "X-900" was reused as an active item`,
		`supersession for retired ID "X-900" was dropped`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected %q, got:\n%s", want, joined)
		}
	}
}

func TestCompareUnchangedDocumentsNeedNoBump(t *testing.T) {
	rules := TransitionRules{
		RequireVersionIncreaseOnChange:   true,
		RequireReviewDateAdvanceOnChange: true,
		RequireMajorOnSchemaChange:       true,
	}
	if errs := Compare(baseSnapshot(), baseSnapshot(), false, rules, Labels{IDNoun: "item"}); len(errs) > 0 {
		t.Fatalf("unchanged snapshots rejected:\n%s", errs)
	}
}
