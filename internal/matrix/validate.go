package matrix

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sofired/tracedoc/internal/check"
	"github.com/sofired/tracedoc/internal/document"
	"github.com/sofired/tracedoc/internal/semver"
)

// Schema-owned lexical rules. These belong to the versioned document schema,
// not to consumer policy: changing them is a schema revision.
var (
	// RequirementIDPattern is the stable requirement-identifier format.
	RequirementIDPattern = check.StableIDPattern
	// StandardKeyPattern is the stable standard-key format.
	StandardKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:[-.][A-Z0-9]+)*$`)

	applicabilityValues  = check.StringSet("applicable", "deferred", "not-applicable")
	evidenceStatusValues = check.StringSet(
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

type validator struct {
	check.Checker
	policy           Policy
	standardKeys     map[string]struct{}
	activeIDs        map[string]struct{}
	coveredStandards map[string]struct{}
	retiredIDs       map[string]struct{}
}

// Validate checks one document snapshot against the schema and the policy.
func Validate(doc Document, policy Policy) check.Errors {
	v := validator{
		policy:           policy,
		standardKeys:     make(map[string]struct{}, len(doc.Standards)),
		activeIDs:        make(map[string]struct{}, len(doc.Requirements)),
		coveredStandards: make(map[string]struct{}, len(doc.Standards)),
		retiredIDs:       make(map[string]struct{}, len(doc.Supersessions)),
	}
	v.document(doc)
	return v.Errs
}

func (v *validator) document(doc Document) {
	if doc.DocumentType != string(document.TypeRequirements) {
		v.Addf("document_type", "expected %q", document.TypeRequirements)
	}
	if doc.SchemaVersion != SchemaVersion {
		v.Addf("schema_version", "expected %d", SchemaVersion)
	}
	v.documentVersion(doc.DocumentVersion)
	v.lastReviewed(doc.LastReviewed)

	if len(doc.Standards) == 0 {
		v.Add("standards", "expected a non-empty array")
	}
	for index, item := range doc.Standards {
		v.standard(index, item)
	}
	for _, key := range check.SortedSetDifference(v.policy.RequiredStandards, v.standardKeys) {
		v.Addf("standards", "required standard %q is missing", key)
	}

	if len(doc.Requirements) == 0 {
		v.Add("requirements", "expected a non-empty array")
	}
	for index, item := range doc.Requirements {
		v.requirement(index, item)
	}
	for _, key := range check.SortedSetDifference(v.standardKeys, v.coveredStandards) {
		v.Addf("standards", "%q has no requirement", key)
	}

	if doc.Supersessions == nil {
		v.Add("supersessions", "expected an array")
	}
	for index, item := range doc.Supersessions {
		v.supersession(index, item)
	}
}

func (v *validator) documentVersion(value string) {
	if v.RequiredString("document_version", value) &&
		!semver.Pattern.MatchString(value) {
		v.Add("document_version", "expected a semantic version")
	}
}

func (v *validator) lastReviewed(value string) {
	if v.RequiredString("last_reviewed", value) {
		if parsed, err := time.Parse(time.DateOnly, value); err != nil ||
			parsed.Format(time.DateOnly) != value {
			v.Add("last_reviewed", "expected an RFC 3339 full date")
		}
	}
}

func (v *validator) standard(index int, item Standard) {
	location := fmt.Sprintf("standards[%d]", index)
	if !StandardKeyPattern.MatchString(item.Key) {
		v.Add(location+".key", "expected a stable standard key")
	} else if !v.InsertUnique(v.standardKeys, item.Key) {
		v.Addf(location+".key", "duplicate standard key %q", item.Key)
	}
	v.RequiredString(location+".title", item.Title)
	v.sourceURI(location+".uri", item.Key, item.URI)
}

func (v *validator) requirement(index int, item Requirement) {
	location := fmt.Sprintf("requirements[%d]", index)
	if !RequirementIDPattern.MatchString(item.ID) {
		v.Add(location+".id", "expected a stable requirement ID")
	} else if !v.InsertUnique(v.activeIDs, item.ID) {
		v.Addf(location+".id", "duplicate requirement ID %q", item.ID)
	}
	v.RequiredString(location+".title", item.Title)
	v.RequiredString(location+".interpretation", item.Interpretation)

	if !check.Contains(v.standardKeys, item.Standard) {
		v.Addf(location+".standard", "unknown standard %q", item.Standard)
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
		v.Add(location+".citations", "expected at least one citation")
	}
	seen := make(map[string]struct{}, len(citations))
	primaryCited := false
	for index, item := range citations {
		itemLocation := fmt.Sprintf("%s.citations[%d]", location, index)
		if item.Standard == primaryStandard {
			primaryCited = true
		}
		standardKnown := check.Contains(v.standardKeys, item.Standard)
		if !standardKnown {
			v.Addf(itemLocation+".standard", "unknown standard %q", item.Standard)
		}
		v.RequiredString(itemLocation+".clause", item.Clause)
		// An unknown standard has no source policy to apply, so the policy
		// half of the URI check is skipped to avoid cascading a second,
		// uninformative "no URI policy" diagnostic — but the schema-owned
		// lexical and injection checks still run, so a malformed URI on the
		// same citation is reported in the same validation pass.
		if standardKnown {
			v.sourceURI(itemLocation+".uri", item.Standard, item.URI)
		} else if v.RequiredString(itemLocation+".uri", item.URI) {
			if _, err := check.LexicalURI(item.URI); err != nil {
				v.Add(itemLocation+".uri", err.Error())
			}
		}
		key := item.Standard + "\x00" + item.Clause + "\x00" + item.URI
		if _, duplicate := seen[key]; duplicate {
			v.Add(itemLocation, "duplicate citation")
		}
		seen[key] = struct{}{}
	}
	if len(citations) > 0 &&
		check.Contains(v.standardKeys, primaryStandard) &&
		!primaryCited {
		v.Addf(
			location+".citations",
			"expected at least one citation for primary standard %q",
			primaryStandard,
		)
	}
}

func (v *validator) applicability(location string, item Requirement) {
	if !v.Enum(location+".applicability", item.Applicability, applicabilityValues) {
		return
	}
	rationaleLocation := location + ".applicability_rationale"
	if item.Applicability != "applicable" {
		if !check.Nonempty(item.ApplicabilityRationale) {
			v.Addf(rationaleLocation, "required for %s", item.Applicability)
		} else {
			v.RequiredString(rationaleLocation, item.ApplicabilityRationale)
		}
	} else if item.ApplicabilityRationale != "" {
		v.RequiredString(rationaleLocation, item.ApplicabilityRationale)
	}
}

func (v *validator) owner(location string, item *Owner) {
	if item == nil {
		v.Add(location+".owner", "expected an object")
		return
	}
	location += ".owner"
	// Bounds before pattern; see check.BoundedControlFreeString for why.
	if v.BoundedControlFreeString(location+".milestone", item.Milestone) &&
		(v.policy.Milestone == nil || !v.policy.Milestone.MatchString(item.Milestone)) {
		v.Add(location+".milestone", "invalid milestone")
	}
	if item.Issue != nil &&
		v.BoundedControlFreeString(location+".issue", *item.Issue) &&
		(v.policy.Issue == nil || !v.policy.Issue.MatchString(*item.Issue)) {
		v.Add(location+".issue", "invalid issue reference")
	}
	if !check.Contains(v.policy.Workstreams, item.Workstream) {
		v.Add(location+".workstream", "unknown workstream")
	}
}

func (v *validator) verification(location string, item *Verification) {
	if item == nil {
		v.Add(location+".planned_verification", "expected an object")
		return
	}
	location += ".planned_verification"
	if v.StringList(location+".levels", item.Levels, true) {
		var unknown []string
		for _, level := range item.Levels {
			if !check.Contains(v.policy.VerificationLevels, level) {
				unknown = append(unknown, level)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			v.Addf(location+".levels", "unsupported values %q", unknown)
		}
	}
	v.StringList(location+".evidence", item.Evidence, true)
}

func (v *validator) evidenceStatus(location string, item Requirement) {
	location += ".evidence_status"
	if !v.Enum(location, item.EvidenceStatus, evidenceStatusValues) {
		return
	}
	switch item.Applicability {
	case "deferred":
		if item.EvidenceStatus != "deferred" {
			v.Add(location, "deferred item must be deferred")
		}
	case "not-applicable":
		if item.EvidenceStatus != "not-applicable" {
			v.Add(location, "not-applicable item must be not-applicable")
		}
	case "applicable":
		if item.EvidenceStatus == "deferred" || item.EvidenceStatus == "not-applicable" {
			v.Add(location, "applicable item has incompatible status")
		}
	}
}

func (v *validator) traceability(location string, item *Traceability) {
	if item == nil {
		v.Add(location+".traceability", "expected an object")
		return
	}
	location += ".traceability"
	v.StringList(location+".adrs", item.ADRs, false)
	v.StringList(location+".threats", item.Threats, false)
	if v.StringList(location+".risks", item.Risks, false) {
		for index, risk := range item.Risks {
			// StringList already rejected control-bearing items, so a value
			// reaching here only needs the consumer pattern applied.
			itemLocation := fmt.Sprintf("%s.risks[%d]", location, index)
			if v.policy.Risk == nil || !v.policy.Risk.MatchString(risk) {
				v.Addf(itemLocation, "invalid risk %q", risk)
			}
		}
	}
}

func (v *validator) supersession(index int, item Supersession) {
	location := fmt.Sprintf("supersessions[%d]", index)
	if !RequirementIDPattern.MatchString(item.RetiredID) {
		v.Add(location+".retired_id", "invalid requirement ID")
	} else if !v.InsertUnique(v.retiredIDs, item.RetiredID) {
		v.Addf(location+".retired_id", "duplicate retired ID %q", item.RetiredID)
	}
	if check.Contains(v.activeIDs, item.RetiredID) {
		v.Add(location+".retired_id", "retired ID is still active")
	}
	// An empty replacement set is legal and records withdrawal without a
	// successor; the member itself stays required so withdrawal is always
	// an explicit act.
	//
	// Chained supersessions (retiring an ID listed as a replacement) are a
	// schema-2 candidate: https://github.com/sofired/tracedoc/issues/3
	if v.StringList(location+".replacement_ids", item.ReplacementIDs, false) {
		for _, replacementID := range item.ReplacementIDs {
			if !check.Contains(v.activeIDs, replacementID) {
				v.Addf(location+".replacement_ids", "unknown active ID %q", replacementID)
			}
		}
	}
	v.RequiredString(location+".rationale", item.Rationale)
}

func (v *validator) sourceURI(location, standardKey, value string) {
	if !v.RequiredString(location, value) {
		return
	}
	if err := validateSourceURI(v.policy, standardKey, value); err != nil {
		v.Add(location, err.Error())
	}
}

func validateSourceURI(policy Policy, standardKey, value string) error {
	parsed, err := check.LexicalURI(value)
	if err != nil {
		return err
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
