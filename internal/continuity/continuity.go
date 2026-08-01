// Package continuity enforces the document-type-independent cross-version
// rules between a designated accepted baseline and a candidate snapshot:
// stable-ID retention, supersession-ledger integrity, and the configured
// version-transition rules.
package continuity

import (
	"fmt"
	"sort"

	"github.com/sofired/matrix-service/internal/check"
	"github.com/sofired/matrix-service/internal/semver"
)

// TransitionRules selects the optional cross-version transition checks the
// compare operation enforces beyond the always-on identity rules.
type TransitionRules struct {
	RequireVersionIncreaseOnChange   bool
	RequireReviewDateAdvanceOnChange bool
	RequireMajorOnSchemaChange       bool
}

// Snapshot is the doctype-independent view of one validated document that
// the continuity rules operate on.
type Snapshot struct {
	SchemaVersion int
	Version       string
	LastReviewed  string
	ActiveIDs     map[string]struct{}
	Supersessions map[string][]string
}

// Labels customizes messages for the document type under comparison.
type Labels struct {
	IDNoun string
}

// Compare checks that candidate is a legal successor of baseline. Both
// snapshots must come from documents that already passed validation.
// The changed flag is computed by the caller over the full documents
// (only the concrete document type can compare every field).
func Compare(
	baseline Snapshot,
	candidate Snapshot,
	changed bool,
	rules TransitionRules,
	labels Labels,
) check.Errors {
	var errs check.Errors
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	for _, id := range sortedKeys(baseline.ActiveIDs) {
		if _, active := candidate.ActiveIDs[id]; active {
			continue
		}
		if _, retired := candidate.Supersessions[id]; !retired {
			add(
				"%s %q was removed without a retained supersession",
				labels.IDNoun,
				id,
			)
		}
	}

	for _, id := range sortedKeys(baseline.Supersessions) {
		if _, active := candidate.ActiveIDs[id]; active {
			add(
				"retired %s ID %q was reused as an active %s",
				labels.IDNoun,
				id,
				labels.IDNoun,
			)
		}
		retained, ok := candidate.Supersessions[id]
		if !ok {
			add("supersession for retired ID %q was dropped", id)
			continue
		}
		if !equalStringSets(baseline.Supersessions[id], retained) {
			add("replacement IDs for retired ID %q changed", id)
		}
	}

	baselineVersion := semver.Parse(baseline.Version)
	candidateVersion := semver.Parse(candidate.Version)
	versionOrder := semver.Compare(candidateVersion, baselineVersion)

	if versionOrder < 0 {
		add(
			"document_version %q is lower than baseline %q",
			candidate.Version,
			baseline.Version,
		)
	}
	if rules.RequireVersionIncreaseOnChange && changed && versionOrder <= 0 {
		add(
			"document changed but document_version %q does not increase baseline %q",
			candidate.Version,
			baseline.Version,
		)
	}
	if rules.RequireReviewDateAdvanceOnChange && changed &&
		candidate.LastReviewed < baseline.LastReviewed {
		add(
			"document changed but last_reviewed %q is earlier than baseline %q",
			candidate.LastReviewed,
			baseline.LastReviewed,
		)
	}
	// Schema transitions are observable here only to a tool release that
	// reads more than one schema version for the document type; the CLI
	// validates both documents first, so while exactly one schema version
	// is readable this rule is a declared forward-looking contract for the
	// first schema migration.
	if rules.RequireMajorOnSchemaChange &&
		candidate.SchemaVersion != baseline.SchemaVersion &&
		candidateVersion.Major() <= baselineVersion.Major() {
		add(
			"schema_version changed from %d to %d without a major document_version increase",
			baseline.SchemaVersion,
			candidate.SchemaVersion,
		)
	}

	return errs
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
