package threats

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sofired/matrix-service/internal/check"
	"github.com/sofired/matrix-service/internal/document"
	"github.com/sofired/matrix-service/internal/semver"
)

// Schema-owned lexical rules and vocabularies. These belong to the
// versioned document schema, not to consumer policy: the coupling rules
// below depend on the exact values, so changing them is a schema revision.
var (
	// ThreatIDPattern is the stable threat-identifier format.
	ThreatIDPattern = check.StableIDPattern
	// AssetIDPattern is the asset-identifier format.
	AssetIDPattern = regexp.MustCompile(`^AST-[0-9]{3}$`)
	// BoundaryIDPattern is the trust-boundary-identifier format.
	BoundaryIDPattern = regexp.MustCompile(`^TB-[0-9]{3}$`)

	severityValues    = check.StringSet("critical", "high", "medium", "low")
	dispositionValues = check.StringSet(
		"open", "mitigated", "accepted", "transferred", "avoided",
	)
	rationaleRequired = check.StringSet("accepted", "transferred", "avoided")
)

// SeverityOrder is the schema-owned display order for severities.
var SeverityOrder = []string{"critical", "high", "medium", "low"}

// DispositionOrder is the schema-owned display order for dispositions.
var DispositionOrder = []string{
	"open", "mitigated", "accepted", "transferred", "avoided",
}

// Policy is the compiled consumer policy the validator applies on top of
// the schema-owned rules.
type Policy struct {
	Workstreams map[string]struct{}
	Milestone   *regexp.Regexp
	Issue       *regexp.Regexp
	Risk        *regexp.Regexp
}

// RequirementIndex resolves requirement links against a validated
// requirements matrix. A nil index limits link checking to the identifier
// format.
type RequirementIndex struct {
	Active       map[string]struct{}
	Retired      map[string]struct{}
	Replacements map[string][]string
}

type validator struct {
	check.Checker
	policy             Policy
	requirements       *RequirementIndex
	assetIDs           map[string]struct{}
	boundaryIDs        map[string]struct{}
	threatIDs          map[string]struct{}
	retiredIDs         map[string]struct{}
	referencedAsset    map[string]struct{}
	referencedBoundary map[string]struct{}
}

// Validate checks one threat-model snapshot against the schema and the
// policy. When requirements is non-nil, requirement links are resolved
// against it; otherwise only their format is checked.
func Validate(doc Document, policy Policy, requirements *RequirementIndex) check.Errors {
	v := validator{
		policy:             policy,
		requirements:       requirements,
		assetIDs:           make(map[string]struct{}, len(doc.Assets)),
		boundaryIDs:        make(map[string]struct{}, len(doc.TrustBoundaries)),
		threatIDs:          make(map[string]struct{}, len(doc.Threats)),
		retiredIDs:         make(map[string]struct{}, len(doc.Supersessions)),
		referencedAsset:    make(map[string]struct{}, len(doc.Assets)),
		referencedBoundary: make(map[string]struct{}, len(doc.TrustBoundaries)),
	}
	v.document(doc)
	return v.Errs
}

func (v *validator) document(doc Document) {
	if doc.DocumentType != string(document.TypeThreatModel) {
		v.Addf("document_type", "expected %q", document.TypeThreatModel)
	}
	if doc.SchemaVersion != SchemaVersion {
		v.Addf("schema_version", "expected %d", SchemaVersion)
	}
	if v.RequiredString("document_version", doc.DocumentVersion) &&
		!semver.Pattern.MatchString(doc.DocumentVersion) {
		v.Add("document_version", "expected a semantic version")
	}
	if v.RequiredString("last_reviewed", doc.LastReviewed) {
		if parsed, err := time.Parse(time.DateOnly, doc.LastReviewed); err != nil ||
			parsed.Format(time.DateOnly) != doc.LastReviewed {
			v.Add("last_reviewed", "expected an RFC 3339 full date")
		}
	}

	if len(doc.Assets) == 0 {
		v.Add("assets", "expected a non-empty array")
	}
	for index, item := range doc.Assets {
		v.namedEntity(
			fmt.Sprintf("assets[%d]", index),
			item.ID, item.Name, item.Description,
			AssetIDPattern, "asset ID", v.assetIDs,
		)
	}

	if len(doc.TrustBoundaries) == 0 {
		v.Add("trust_boundaries", "expected a non-empty array")
	}
	for index, item := range doc.TrustBoundaries {
		v.namedEntity(
			fmt.Sprintf("trust_boundaries[%d]", index),
			item.ID, item.Name, item.Description,
			BoundaryIDPattern, "trust-boundary ID", v.boundaryIDs,
		)
	}

	if len(doc.Threats) == 0 {
		v.Add("threats", "expected a non-empty array")
	}
	for index, item := range doc.Threats {
		v.threat(index, item)
	}
	for _, id := range check.SortedSetDifference(v.assetIDs, v.referencedAsset) {
		v.Addf("assets", "%q has no referencing threat", id)
	}
	for _, id := range check.SortedSetDifference(v.boundaryIDs, v.referencedBoundary) {
		v.Addf("trust_boundaries", "%q has no referencing threat", id)
	}

	if doc.Supersessions == nil {
		v.Add("supersessions", "expected an array")
	}
	for index, item := range doc.Supersessions {
		v.supersession(index, item)
	}
}

func (v *validator) namedEntity(
	location string,
	id string,
	name string,
	description string,
	pattern *regexp.Regexp,
	label string,
	ids map[string]struct{},
) {
	if !pattern.MatchString(id) {
		v.Addf(location+".id", "expected a stable %s", label)
	} else if !v.InsertUnique(ids, id) {
		v.Addf(location+".id", "duplicate %s %q", label, id)
	}
	v.RequiredString(location+".name", name)
	v.RequiredString(location+".description", description)
}

func (v *validator) threat(index int, item Threat) {
	location := fmt.Sprintf("threats[%d]", index)
	switch {
	case !ThreatIDPattern.MatchString(item.ID):
		v.Add(location+".id", "expected a stable threat ID")
	case AssetIDPattern.MatchString(item.ID) || BoundaryIDPattern.MatchString(item.ID):
		v.Add(location+".id", "threat IDs must not use the asset or trust-boundary prefix")
	case !v.InsertUnique(v.threatIDs, item.ID):
		v.Addf(location+".id", "duplicate threat ID %q", item.ID)
	}
	v.RequiredString(location+".title", item.Title)
	v.RequiredString(location+".description", item.Description)

	v.Enum(location+".severity", item.Severity, severityValues)
	dispositionKnown := v.Enum(location+".disposition", item.Disposition, dispositionValues)
	v.dispositionRationale(location, item, dispositionKnown)

	if v.StringList(location+".affected_assets", item.AffectedAssets, true) {
		for itemIndex, id := range item.AffectedAssets {
			if !check.Contains(v.assetIDs, id) {
				v.Addf(
					fmt.Sprintf("%s.affected_assets[%d]", location, itemIndex),
					"unknown asset %q", id,
				)
			}
			v.referencedAsset[id] = struct{}{}
		}
	}
	if v.StringList(location+".trust_boundaries", item.TrustBoundaries, false) {
		for itemIndex, id := range item.TrustBoundaries {
			if !check.Contains(v.boundaryIDs, id) {
				v.Addf(
					fmt.Sprintf("%s.trust_boundaries[%d]", location, itemIndex),
					"unknown trust boundary %q", id,
				)
			}
			v.referencedBoundary[id] = struct{}{}
		}
	}

	v.owner(location, item.Owner)
	v.mitigations(location, item)
}

func (v *validator) dispositionRationale(location string, item Threat, dispositionKnown bool) {
	rationaleLocation := location + ".disposition_rationale"
	if dispositionKnown && check.Contains(rationaleRequired, item.Disposition) {
		if !check.Nonempty(item.DispositionRationale) {
			v.Addf(rationaleLocation, "required for %s", item.Disposition)
			return
		}
	}
	if item.DispositionRationale != "" {
		v.RequiredString(rationaleLocation, item.DispositionRationale)
	}
}

func (v *validator) owner(location string, item *Owner) {
	if item == nil {
		v.Add(location+".owner", "expected an object")
		return
	}
	location += ".owner"
	if v.policy.Milestone == nil || !v.policy.Milestone.MatchString(item.Milestone) {
		v.Add(location+".milestone", "invalid milestone")
	}
	if item.Issue != nil &&
		(v.policy.Issue == nil || !v.policy.Issue.MatchString(*item.Issue)) {
		v.Add(location+".issue", "invalid issue reference")
	}
	if !check.Contains(v.policy.Workstreams, item.Workstream) {
		v.Add(location+".workstream", "unknown workstream")
	}
}

func (v *validator) mitigations(location string, item Threat) {
	if item.Mitigations == nil {
		v.Add(location+".mitigations", "expected an object")
		return
	}
	mitigations := item.Mitigations
	mitigationsLocation := location + ".mitigations"
	v.StringList(mitigationsLocation+".adrs", mitigations.ADRs, false)
	v.StringList(mitigationsLocation+".tests", mitigations.Tests, false)

	if v.StringList(mitigationsLocation+".requirements", mitigations.Requirements, false) {
		for index, id := range mitigations.Requirements {
			v.requirementLink(
				fmt.Sprintf("%s.requirements[%d]", mitigationsLocation, index),
				id,
			)
		}
	}
	if v.StringList(mitigationsLocation+".risks", mitigations.Risks, false) {
		for index, risk := range mitigations.Risks {
			if v.policy.Risk == nil || !v.policy.Risk.MatchString(risk) {
				v.Addf(
					fmt.Sprintf("%s.risks[%d]", mitigationsLocation, index),
					"invalid risk %q", risk,
				)
			}
		}
	}

	switch item.Disposition {
	case "mitigated":
		if len(mitigations.ADRs)+len(mitigations.Requirements)+len(mitigations.Tests) == 0 {
			v.Add(
				mitigationsLocation,
				"mitigated threat requires at least one ADR, requirement, or test",
			)
		}
	case "accepted":
		if len(mitigations.Risks) == 0 {
			v.Add(
				mitigationsLocation,
				"accepted threat requires at least one risk record",
			)
		}
	}
}

func (v *validator) requirementLink(location, id string) {
	if !check.StableIDPattern.MatchString(id) {
		v.Addf(location, "invalid requirement ID %q", id)
		return
	}
	if v.requirements == nil {
		return
	}
	if check.Contains(v.requirements.Active, id) {
		return
	}
	if check.Contains(v.requirements.Retired, id) {
		if replacements := v.requirements.Replacements[id]; len(replacements) > 0 {
			v.Addf(
				location,
				"requirement %q is retired; replacements: %s",
				id,
				strings.Join(replacements, ", "),
			)
		} else {
			v.Addf(location, "requirement %q was withdrawn without a replacement", id)
		}
		return
	}
	v.Addf(location, "unknown requirement %q", id)
}

func (v *validator) supersession(index int, item Supersession) {
	location := fmt.Sprintf("supersessions[%d]", index)
	if !ThreatIDPattern.MatchString(item.RetiredID) {
		v.Add(location+".retired_id", "invalid threat ID")
	} else if !v.InsertUnique(v.retiredIDs, item.RetiredID) {
		v.Addf(location+".retired_id", "duplicate retired ID %q", item.RetiredID)
	}
	if check.Contains(v.threatIDs, item.RetiredID) {
		v.Add(location+".retired_id", "retired ID is still active")
	}
	// An empty replacement set is legal and records withdrawal without a
	// successor; the member itself stays required so withdrawal is always
	// an explicit act.
	if v.StringList(location+".replacement_ids", item.ReplacementIDs, false) {
		for _, replacementID := range item.ReplacementIDs {
			if !check.Contains(v.threatIDs, replacementID) {
				v.Addf(location+".replacement_ids", "unknown active ID %q", replacementID)
			}
		}
	}
	v.RequiredString(location+".rationale", item.Rationale)
}
