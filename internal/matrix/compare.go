package matrix

import (
	"reflect"

	"github.com/sofired/matrix-service/internal/check"
	"github.com/sofired/matrix-service/internal/continuity"
)

// Compare checks that candidate is a legal successor of the designated
// accepted baseline. Both documents must already pass Validate; the
// cross-version rules themselves live in the continuity package.
func Compare(
	baseline Document,
	candidate Document,
	rules continuity.TransitionRules,
) check.Errors {
	// DeepEqual distinguishes nil from empty slices, which is safe only
	// because Validate forces every schema-1 slice and object field to be
	// non-nil. A future schema that adds an optional array field must
	// normalize here before comparing.
	changed := !reflect.DeepEqual(baseline, candidate)
	return continuity.Compare(
		snapshot(baseline),
		snapshot(candidate),
		changed,
		rules,
		continuity.Labels{IDNoun: "requirement"},
	)
}

func snapshot(doc Document) continuity.Snapshot {
	active := make(map[string]struct{}, len(doc.Requirements))
	for _, item := range doc.Requirements {
		active[item.ID] = struct{}{}
	}
	supersessions := make(map[string][]string, len(doc.Supersessions))
	for _, item := range doc.Supersessions {
		supersessions[item.RetiredID] = item.ReplacementIDs
	}
	return continuity.Snapshot{
		SchemaVersion: doc.SchemaVersion,
		Version:       doc.DocumentVersion,
		LastReviewed:  doc.LastReviewed,
		ActiveIDs:     active,
		Supersessions: supersessions,
	}
}
