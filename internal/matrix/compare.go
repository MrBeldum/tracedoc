package matrix

import (
	"fmt"
	"reflect"
	"sort"
)

// TransitionRules selects the optional cross-version transition checks the
// compare operation enforces beyond the always-on identity rules.
type TransitionRules struct {
	RequireVersionIncreaseOnChange   bool
	RequireReviewDateAdvanceOnChange bool
	RequireMajorOnSchemaChange       bool
}

// Compare checks that candidate is a legal successor of the designated
// accepted baseline. Both documents must already pass Validate; Compare
// enforces only cross-version rules:
//
//   - every requirement ID active in the baseline stays active or is retired
//     through a supersession retained in the candidate;
//   - IDs retired in the baseline are never reactivated and their
//     supersession entries are retained with unchanged replacement IDs; and
//   - the configured version-transition rules hold for matrix_version,
//     last_reviewed, and schema_version.
func Compare(baseline, candidate Document, rules TransitionRules) Errors {
	var errs Errors
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	baselineActive := requirementIDs(baseline)
	candidateActive := requirementIDs(candidate)
	baselineRetired := supersessionsByRetiredID(baseline)
	candidateRetired := supersessionsByRetiredID(candidate)

	for _, id := range sortedKeys(baselineActive) {
		if _, active := candidateActive[id]; active {
			continue
		}
		if _, retired := candidateRetired[id]; !retired {
			add(
				"requirement %q was removed without a retained supersession",
				id,
			)
		}
	}

	for _, id := range sortedKeys(baselineRetired) {
		if _, active := candidateActive[id]; active {
			add("retired requirement ID %q was reused as an active requirement", id)
		}
		retained, ok := candidateRetired[id]
		if !ok {
			add("supersession for retired ID %q was dropped", id)
			continue
		}
		if !equalStringSets(baselineRetired[id].ReplacementIDs, retained.ReplacementIDs) {
			add("replacement IDs for retired ID %q changed", id)
		}
	}

	// DeepEqual distinguishes nil from empty slices, which is safe only
	// because Validate forces every schema-1 slice and object field to be
	// non-nil. A future schema that adds an optional array field must
	// normalize here before comparing.
	changed := !reflect.DeepEqual(baseline, candidate)
	baselineVersion := parseSemver(baseline.MatrixVersion)
	candidateVersion := parseSemver(candidate.MatrixVersion)
	versionOrder := compareSemver(candidateVersion, baselineVersion)

	if versionOrder < 0 {
		add(
			"matrix_version %q is lower than baseline %q",
			candidate.MatrixVersion,
			baseline.MatrixVersion,
		)
	}
	if rules.RequireVersionIncreaseOnChange && changed && versionOrder <= 0 {
		add(
			"matrix changed but matrix_version %q does not increase baseline %q",
			candidate.MatrixVersion,
			baseline.MatrixVersion,
		)
	}
	if rules.RequireReviewDateAdvanceOnChange && changed &&
		candidate.LastReviewed < baseline.LastReviewed {
		add(
			"matrix changed but last_reviewed %q is earlier than baseline %q",
			candidate.LastReviewed,
			baseline.LastReviewed,
		)
	}
	// Schema transitions are observable here only to a tool release that
	// reads more than one schema version; the CLI validates both documents
	// first, so while exactly one schema version is readable this rule is a
	// declared forward-looking contract for the first schema migration.
	if rules.RequireMajorOnSchemaChange &&
		candidate.SchemaVersion != baseline.SchemaVersion &&
		candidateVersion.numbers[0] <= baselineVersion.numbers[0] {
		add(
			"schema_version changed from %d to %d without a major matrix_version increase",
			baseline.SchemaVersion,
			candidate.SchemaVersion,
		)
	}

	return errs
}

func requirementIDs(doc Document) map[string]struct{} {
	result := make(map[string]struct{}, len(doc.Requirements))
	for _, item := range doc.Requirements {
		result[item.ID] = struct{}{}
	}
	return result
}

func supersessionsByRetiredID(doc Document) map[string]Supersession {
	result := make(map[string]Supersession, len(doc.Supersessions))
	for _, item := range doc.Supersessions {
		result[item.RetiredID] = item
	}
	return result
}

func equalStringSets(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftSorted := append([]string(nil), left...)
	rightSorted := append([]string(nil), right...)
	sort.Strings(leftSorted)
	sort.Strings(rightSorted)
	for index := range leftSorted {
		if leftSorted[index] != rightSorted[index] {
			return false
		}
	}
	return true
}

func sortedKeys[V any](values map[string]V) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
