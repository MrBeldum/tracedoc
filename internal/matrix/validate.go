package matrix

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Schema-owned lexical rules. These belong to the versioned document schema,
// not to consumer policy: changing them is a schema revision.
var (
	// RequirementIDPattern is the stable requirement-identifier format.
	RequirementIDPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[0-9]{3}$`)
	// StandardKeyPattern is the stable standard-key format.
	StandardKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:[-.][A-Z0-9]+)*$`)
	// MatrixVersionPattern is the semantic-version format for matrix_version.
	MatrixVersionPattern = regexp.MustCompile(
		`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
			`(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)` +
			`(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?` +
			`(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`,
	)

	applicabilityValues  = stringSet("applicable", "deferred", "not-applicable")
	evidenceStatusValues = stringSet(
		"planned", "in-progress", "verified", "deferred", "not-applicable",
	)
)

// EvidenceStatusOrder is the schema-owned display order for evidence states.
var EvidenceStatusOrder = []string{
	"planned", "in-progress", "verified", "deferred", "not-applicable",
}

// ApplicabilityOrder is the schema-owned display order for applicability.
var ApplicabilityOrder = []string{"applicable", "deferred", "not-applicable"}

// Policy is the compiled consumer policy the validator applies on top of the
// schema-owned rules.
type Policy struct {
	RequiredStandards  map[string]struct{}
	StandardHosts      map[string]string
	LocalSources       map[string]string
	Workstreams        map[string]struct{}
	VerificationLevels map[string]struct{}
	Milestone          *regexp.Regexp
	Issue              *regexp.Regexp
	Risk               *regexp.Regexp
}

// Errors is an ordered list of validation failures.
type Errors []string

func (errs Errors) Error() string {
	return strings.Join(errs, "\n")
}

type validator struct {
	policy           Policy
	errs             Errors
	standardKeys     map[string]struct{}
	activeIDs        map[string]struct{}
	coveredStandards map[string]struct{}
	retiredIDs       map[string]struct{}
}

// Validate checks one document snapshot against the schema and the policy.
func Validate(doc Document, policy Policy) Errors {
	v := validator{
		policy:           policy,
		standardKeys:     make(map[string]struct{}, len(doc.Standards)),
		activeIDs:        make(map[string]struct{}, len(doc.Requirements)),
		coveredStandards: make(map[string]struct{}, len(doc.Standards)),
		retiredIDs:       make(map[string]struct{}, len(doc.Supersessions)),
	}
	v.document(doc)
	return v.errs
}

func (v *validator) document(doc Document) {
	if doc.SchemaVersion != SchemaVersion {
		v.addf("schema_version", "expected %d", SchemaVersion)
	}
	if v.requiredString("matrix_version", doc.MatrixVersion) &&
		!MatrixVersionPattern.MatchString(doc.MatrixVersion) {
		v.add("matrix_version", "expected a semantic version")
	}
	if v.requiredString("last_reviewed", doc.LastReviewed) {
		if parsed, err := time.Parse(time.DateOnly, doc.LastReviewed); err != nil ||
			parsed.Format(time.DateOnly) != doc.LastReviewed {
			v.add("last_reviewed", "expected an RFC 3339 full date")
		}
	}

	if len(doc.Standards) == 0 {
		v.add("standards", "expected a non-empty array")
	}
	for index, item := range doc.Standards {
		v.standard(index, item)
	}
	for _, key := range sortedSetDifference(v.policy.RequiredStandards, v.standardKeys) {
		v.addf("standards", "required standard %q is missing", key)
	}

	if len(doc.Requirements) == 0 {
		v.add("requirements", "expected a non-empty array")
	}
	for index, item := range doc.Requirements {
		v.requirement(index, item)
	}
	for _, key := range sortedSetDifference(v.standardKeys, v.coveredStandards) {
		v.addf("standards", "%q has no requirement", key)
	}

	if doc.Supersessions == nil {
		v.add("supersessions", "expected an array")
	}
	for index, item := range doc.Supersessions {
		v.supersession(index, item)
	}
}

func (v *validator) standard(index int, item Standard) {
	location := fmt.Sprintf("standards[%d]", index)
	if !StandardKeyPattern.MatchString(item.Key) {
		v.add(location+".key", "expected a stable standard key")
	} else if !v.insertUnique(v.standardKeys, item.Key) {
		v.addf(location+".key", "duplicate standard key %q", item.Key)
	}
	v.requiredString(location+".title", item.Title)
	v.sourceURI(location+".uri", item.Key, item.URI)
}

func (v *validator) requirement(index int, item Requirement) {
	location := fmt.Sprintf("requirements[%d]", index)
	if !RequirementIDPattern.MatchString(item.ID) {
		v.add(location+".id", "expected a stable requirement ID")
	} else if !v.insertUnique(v.activeIDs, item.ID) {
		v.addf(location+".id", "duplicate requirement ID %q", item.ID)
	}
	v.requiredString(location+".title", item.Title)
	v.requiredString(location+".interpretation", item.Interpretation)

	if !contains(v.standardKeys, item.Standard) {
		v.addf(location+".standard", "unknown standard %q", item.Standard)
	} else {
		v.coveredStandards[item.Standard] = struct{}{}
	}

	v.citations(location, item.Standard, item.Citations)
	v.applicability(location, item)
	v.owner(location, item.Owner)
	v.verification(location, item.PlannedVerification)
	v.evidenceStatus(location, item)
	v.traceability(location, item.Traceability)
}

func (v *validator) citations(
	location string,
	primaryStandard string,
	citations []Citation,
) {
	if len(citations) == 0 {
		v.add(location+".citations", "expected at least one citation")
	}
	seen := make(map[string]struct{}, len(citations))
	primaryCited := false
	for index, item := range citations {
		itemLocation := fmt.Sprintf("%s.citations[%d]", location, index)
		if item.Standard == primaryStandard {
			primaryCited = true
		}
		if !contains(v.standardKeys, item.Standard) {
			v.addf(itemLocation+".standard", "unknown standard %q", item.Standard)
		}
		v.requiredString(itemLocation+".clause", item.Clause)
		v.sourceURI(itemLocation+".uri", item.Standard, item.URI)
		key := item.Standard + "\x00" + item.Clause + "\x00" + item.URI
		if _, duplicate := seen[key]; duplicate {
			v.add(itemLocation, "duplicate citation")
		}
		seen[key] = struct{}{}
	}
	if len(citations) > 0 &&
		contains(v.standardKeys, primaryStandard) &&
		!primaryCited {
		v.addf(
			location+".citations",
			"expected at least one citation for primary standard %q",
			primaryStandard,
		)
	}
}

func (v *validator) applicability(location string, item Requirement) {
	if !v.enum(location+".applicability", item.Applicability, applicabilityValues) {
		return
	}
	rationaleLocation := location + ".applicability_rationale"
	if item.Applicability != "applicable" {
		if !nonempty(item.ApplicabilityRationale) {
			v.addf(rationaleLocation, "required for %s", item.Applicability)
		} else {
			v.requiredString(rationaleLocation, item.ApplicabilityRationale)
		}
	} else if item.ApplicabilityRationale != "" {
		v.requiredString(rationaleLocation, item.ApplicabilityRationale)
	}
}

func (v *validator) owner(location string, item *Owner) {
	if item == nil {
		v.add(location+".owner", "expected an object")
		return
	}
	location += ".owner"
	if v.policy.Milestone == nil || !v.policy.Milestone.MatchString(item.Milestone) {
		v.add(location+".milestone", "invalid milestone")
	}
	if item.Issue != nil &&
		(v.policy.Issue == nil || !v.policy.Issue.MatchString(*item.Issue)) {
		v.add(location+".issue", "invalid issue reference")
	}
	if !contains(v.policy.Workstreams, item.Workstream) {
		v.add(location+".workstream", "unknown workstream")
	}
}

func (v *validator) verification(location string, item *Verification) {
	if item == nil {
		v.add(location+".planned_verification", "expected an object")
		return
	}
	location += ".planned_verification"
	if v.stringList(location+".levels", item.Levels, true) {
		var unknown []string
		for _, level := range item.Levels {
			if !contains(v.policy.VerificationLevels, level) {
				unknown = append(unknown, level)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			v.addf(location+".levels", "unsupported values %q", unknown)
		}
	}
	v.stringList(location+".evidence", item.Evidence, true)
}

func (v *validator) evidenceStatus(location string, item Requirement) {
	location += ".evidence_status"
	if !v.enum(location, item.EvidenceStatus, evidenceStatusValues) {
		return
	}
	switch item.Applicability {
	case "deferred":
		if item.EvidenceStatus != "deferred" {
			v.add(location, "deferred item must be deferred")
		}
	case "not-applicable":
		if item.EvidenceStatus != "not-applicable" {
			v.add(location, "not-applicable item must be not-applicable")
		}
	case "applicable":
		if item.EvidenceStatus == "deferred" || item.EvidenceStatus == "not-applicable" {
			v.add(location, "applicable item has incompatible status")
		}
	}
}

func (v *validator) traceability(location string, item *Traceability) {
	if item == nil {
		v.add(location+".traceability", "expected an object")
		return
	}
	location += ".traceability"
	v.stringList(location+".adrs", item.ADRs, false)
	v.stringList(location+".threats", item.Threats, false)
	if v.stringList(location+".risks", item.Risks, false) {
		for index, risk := range item.Risks {
			if v.policy.Risk == nil || !v.policy.Risk.MatchString(risk) {
				v.addf(fmt.Sprintf("%s.risks[%d]", location, index), "invalid risk %q", risk)
			}
		}
	}
}

func (v *validator) supersession(index int, item Supersession) {
	location := fmt.Sprintf("supersessions[%d]", index)
	if !RequirementIDPattern.MatchString(item.RetiredID) {
		v.add(location+".retired_id", "invalid requirement ID")
	} else if !v.insertUnique(v.retiredIDs, item.RetiredID) {
		v.addf(location+".retired_id", "duplicate retired ID %q", item.RetiredID)
	}
	if contains(v.activeIDs, item.RetiredID) {
		v.add(location+".retired_id", "retired ID is still active")
	}
	if v.stringList(location+".replacement_ids", item.ReplacementIDs, true) {
		for _, replacementID := range item.ReplacementIDs {
			if !contains(v.activeIDs, replacementID) {
				v.addf(location+".replacement_ids", "unknown active ID %q", replacementID)
			}
		}
	}
	v.requiredString(location+".rationale", item.Rationale)
}

func (v *validator) sourceURI(location, standardKey, value string) {
	if !v.requiredString(location, value) {
		return
	}
	if err := validateSourceURI(v.policy, standardKey, value); err != nil {
		v.add(location, err.Error())
	}
}

func validateSourceURI(policy Policy, standardKey, value string) error {
	if strings.TrimSpace(value) != value ||
		strings.Contains(value, `\`) ||
		strings.IndexFunc(value, func(r rune) bool {
			return unicode.IsControl(r) || unicode.IsSpace(r)
		}) >= 0 {
		return errors.New("contains whitespace, a control character, or a backslash")
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("invalid URI: %w", err)
	}
	if parsed.Opaque != "" || parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" {
		return errors.New("opaque URIs, user information, ports, and queries are not allowed")
	}
	if strings.IndexFunc(parsed.Path+parsed.Fragment, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) >= 0 {
		return errors.New("contains encoded whitespace or a control character")
	}

	if localPath, ok := policy.LocalSources[standardKey]; ok {
		if parsed.Scheme != "" || parsed.Host != "" || parsed.Path != localPath {
			return fmt.Errorf("%s URI must reference %s", standardKey, localPath)
		}
		return nil
	}

	expectedHost, ok := policy.StandardHosts[standardKey]
	if !ok {
		return fmt.Errorf("no URI policy for standard %q", standardKey)
	}
	if parsed.Scheme != "https" || parsed.Host != expectedHost ||
		!strings.HasPrefix(parsed.Path, "/") {
		return fmt.Errorf(
			"expected an HTTPS URI on %s for standard %s",
			expectedHost,
			standardKey,
		)
	}
	return nil
}

func (v *validator) requiredString(location, value string) bool {
	if !nonempty(value) {
		v.add(location, "expected a non-empty string")
		return false
	}
	if len(value) > MaxStringBytes {
		v.addf(location, "exceeds %d-byte limit", MaxStringBytes)
		return false
	}
	return true
}

func (v *validator) stringList(location string, values []string, requireItems bool) bool {
	if values == nil || requireItems && len(values) == 0 {
		expectation := "expected an array"
		if requireItems {
			expectation = "expected a non-empty array"
		}
		v.add(location, expectation)
		return false
	}
	valid := true
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		itemLocation := fmt.Sprintf("%s[%d]", location, index)
		if !v.requiredString(itemLocation, value) {
			valid = false
		}
		if _, duplicate := seen[value]; duplicate {
			v.addf(itemLocation, "duplicate value %q", value)
			valid = false
		}
		seen[value] = struct{}{}
	}
	return valid
}

func (v *validator) enum(
	location string,
	value string,
	allowed map[string]struct{},
) bool {
	if contains(allowed, value) {
		return true
	}
	v.addf(location, "unsupported value %q", value)
	return false
}

func (v *validator) insertUnique(values map[string]struct{}, value string) bool {
	if contains(values, value) {
		return false
	}
	values[value] = struct{}{}
	return true
}

func (v *validator) add(location, message string) {
	v.errs = append(v.errs, location+": "+message)
}

func (v *validator) addf(location, format string, args ...any) {
	v.add(location, fmt.Sprintf(format, args...))
}

func stringSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func contains(values map[string]struct{}, value string) bool {
	_, ok := values[value]
	return ok
}

func nonempty(value string) bool {
	return strings.TrimSpace(value) != ""
}

func sortedSetDifference(left, right map[string]struct{}) []string {
	var result []string
	for value := range left {
		if !contains(right, value) {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
