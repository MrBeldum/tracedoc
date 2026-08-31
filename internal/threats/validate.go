package threats

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sofired/tracedoc/internal/check"
	"github.com/sofired/tracedoc/internal/document"
	"github.com/sofired/tracedoc/internal/semver"
)

// Schema-owned lexical rules and vocabularies. These belong to the
// versioned document schema, not to consumer policy: the coupling and
// coverage rules below depend on the exact values, so changing them is a
// schema revision. Vocabularies that drive no rule — document status,
// control status, evidence level and status — are consumer configuration.
var (
	// ThreatIDPattern is the stable threat-identifier format.
	ThreatIDPattern = check.StableIDPattern
	// AssumptionIDPattern is the assumption-identifier format.
	AssumptionIDPattern = regexp.MustCompile(`^ASM-[0-9]{3}$`)
	// ComponentIDPattern is the component-identifier format.
	ComponentIDPattern = regexp.MustCompile(`^COMP-[0-9]{3}$`)
	// ActorIDPattern is the actor-identifier format.
	ActorIDPattern = regexp.MustCompile(`^ACTOR-[0-9]{3}$`)
	// AssetIDPattern is the asset-identifier format.
	AssetIDPattern = regexp.MustCompile(`^AST-[0-9]{3}$`)
	// BoundaryIDPattern is the trust-boundary-identifier format.
	BoundaryIDPattern = regexp.MustCompile(`^TB-[0-9]{3}$`)
	// FlowIDPattern is the data-flow-identifier format.
	FlowIDPattern = regexp.MustCompile(`^DF-[0-9]{3}$`)
	// EntryPointIDPattern is the entry-point-identifier format.
	EntryPointIDPattern = regexp.MustCompile(`^EP-[0-9]{3}$`)
	// DecisionIDPattern is the decision-record identifier format.
	DecisionIDPattern = regexp.MustCompile(`^ADR-[0-9]{1,6}$`)
	// ControlIDPattern is the control-identifier format.
	ControlIDPattern = regexp.MustCompile(`^CTRL-[0-9]{3}$`)
	// EvidenceIDPattern is the planned-evidence identifier format.
	EvidenceIDPattern = regexp.MustCompile(`^EVD-[0-9]{3}$`)
	// ObservationIDPattern is the observability-record identifier format.
	ObservationIDPattern = regexp.MustCompile(`^OBS-[0-9]{3}$`)

	// reservedIDPrefixes are the entity prefixes a threat ID must not use.
	// Threat IDs are consumer-chosen within the generic stable-ID format, so
	// without this guard a threat could take an ID that reads as — and, in
	// the rendered companion, anchors as — a component or a control.
	reservedIDPrefixes = []string{
		"ASM", "COMP", "ACTOR", "AST", "TB", "DF", "EP", "ADR", "CTRL", "EVD", "OBS",
	}

	ratingValues     = check.StringSet("low", "medium", "high")
	priorityValues   = check.StringSet("critical", "high", "medium", "low")
	treatmentValues  = check.StringSet("mitigate", "accept", "avoid", "transfer")
	decisionStatuses = check.StringSet("proposed", "accepted", "rejected", "superseded")

	// treatmentRationaleRequired names the treatments that record a choice
	// not to fix: each must say why in prose.
	treatmentRationaleRequired = check.StringSet("accept", "avoid", "transfer")
)

// PriorityOrder is the schema-owned display order for threat priorities.
var PriorityOrder = []string{"critical", "high", "medium", "low"}

// TreatmentOrder is the schema-owned display order for treatments.
var TreatmentOrder = []string{"mitigate", "accept", "avoid", "transfer"}

// Limits are the consumer's quantitative policy for the collections whose
// usefulness depends on how much of them there is. They are configuration
// rather than schema rules because the right numbers are a project's
// judgement: a small service may calibrate two priority levels and name
// three headline paths where a platform names ten. Zero disables a limit.
type Limits struct {
	MinCriticalityExamples int
	MinTopAbusePaths       int
	MaxTopAbusePaths       int
}

// Coverage selects which declared-entity coverage rules the validator
// enforces. Each rule answers "was this thing the document declared
// actually analysed?", and each is a named switch rather than a general
// rule language so the set stays bounded and reviewable.
type Coverage struct {
	Assets      bool
	Boundaries  bool
	Flows       bool
	EntryPoints bool
	Controls    bool
	Risks       bool
	Evidence    bool
	// Criticality requires every priority value the schema defines to have
	// a calibration entry. Off, a project may calibrate only the levels it
	// actually uses.
	Criticality bool
}

// Policy is the compiled consumer policy the validator applies on top of
// the schema-owned rules.
type Policy struct {
	Workstreams      map[string]struct{}
	Milestone        *regexp.Regexp
	Issue            *regexp.Regexp
	Risk             *regexp.Regexp
	Owner            *regexp.Regexp
	DocumentStatuses map[string]struct{}
	ControlStatuses  map[string]struct{}
	EvidenceLevels   map[string]struct{}
	EvidenceStatuses map[string]struct{}
	ReferenceHosts   map[string]struct{}
	Coverage         Coverage
	Limits           Limits
}

// RequirementIndex resolves requirement links against a validated
// requirements matrix. A nil index limits link checking to the identifier
// format.
type RequirementIndex struct {
	Active       map[string]struct{}
	Retired      map[string]struct{}
	Replacements map[string][]string
}

// idSet is one declared-entity collection: the IDs it declares, and the
// subset of those a threat actually analysed.
//
// analysed is deliberately not "referenced by anything". A trust boundary
// named by a data flow, or a control named by an observability record, has
// been wired into the model but not reasoned about as an attack surface —
// counting those would make every coverage rule vacuously true, because the
// architecture graph references its own members by construction. Only the
// threat pass and the entry-point rule below mark analysed.
type idSet struct {
	noun     string
	declared map[string]struct{}
	analysed map[string]struct{}
}

func newIDSet(noun string, size int) *idSet {
	return &idSet{
		noun:     noun,
		declared: make(map[string]struct{}, size),
		analysed: make(map[string]struct{}, size),
	}
}

type validator struct {
	check.Checker
	policy       Policy
	requirements *RequirementIndex

	assumptions  *idSet
	components   *idSet
	actors       *idSet
	assets       *idSet
	boundaries   *idSet
	flows        *idSet
	entryPoints  *idSet
	decisions    *idSet
	risks        *idSet
	controls     *idSet
	evidence     *idSet
	observations *idSet
	threats      *idSet

	// allIDs is the document-wide identifier namespace, keyed by the
	// anchor form of each ID and holding the ID as first written. Every
	// declared entity shares one anchor space in the rendered companion,
	// so an ID reused across two collections would silently collapse two
	// anchors into one. Distinct per-type prefixes make that impossible
	// between schema-owned types; risk IDs follow a consumer pattern that
	// this check is the only guard against.
	//
	// Anchors are case-folded, so the key is too: a consumer pattern that
	// admits both "R1" and "r1" yields two distinct IDs that address one
	// anchor, which is the collision this check exists to prevent.
	allIDs     map[string]string
	retiredIDs map[string]struct{}
}

// Validate checks one threat-model snapshot against the schema and the
// policy. When requirements is non-nil, requirement links are resolved
// against it; otherwise only their format is checked.
func Validate(doc Document, policy Policy, requirements *RequirementIndex) check.Errors {
	v := validator{
		policy:       policy,
		requirements: requirements,
		assumptions:  newIDSet("assumption", len(doc.Assumptions)),
		components:   newIDSet("component", len(doc.Components)),
		actors:       newIDSet("actor", len(doc.Actors)),
		assets:       newIDSet("asset", len(doc.Assets)),
		boundaries:   newIDSet("trust boundary", len(doc.TrustBoundaries)),
		flows:        newIDSet("data flow", len(doc.DataFlows)),
		entryPoints:  newIDSet("entry point", len(doc.EntryPoints)),
		decisions:    newIDSet("decision", len(doc.Decisions)),
		risks:        newIDSet("risk", len(doc.Risks)),
		controls:     newIDSet("control", len(doc.Controls)),
		evidence:     newIDSet("planned evidence", len(doc.PlannedEvidence)),
		observations: newIDSet("observation", len(doc.Observability)),
		threats:      newIDSet("threat", len(doc.Threats)),
		allIDs:       make(map[string]string),
		retiredIDs:   make(map[string]struct{}, len(doc.Supersessions)),
	}
	v.document(doc)
	return v.Errs
}

func (v *validator) document(doc Document) {
	v.metadata(doc)
	// Declare every identifier before any body is validated, so a
	// cross-reference is resolved against the complete namespace regardless
	// of the order collections appear in the document.
	v.declareIDs(doc)

	v.scope(doc.Scope)
	// Every slice field must be present, even when empty. Compare relies on
	// reflect.DeepEqual, which distinguishes a nil slice from an empty one,
	// so an omitted array would read as a document change on the next
	// revision that spells it out. Collections with a non-empty rule below
	// get this for free; these optional ones need it stated.
	v.requireArray("assumptions", doc.Assumptions == nil)
	v.requireArray("decisions", doc.Decisions == nil)
	v.requireArray("risks", doc.Risks == nil)
	v.requireArray("observability", doc.Observability == nil)
	v.requireArray("criticality", doc.Criticality == nil)
	v.requireArray("focus_paths", doc.FocusPaths == nil)
	v.assumptionBodies(doc.Assumptions)
	v.StringList("open_questions", doc.OpenQuestions, false)
	v.diagrams(doc.Diagrams)
	v.componentBodies(doc.Components)
	v.actorBodies(doc.Actors)
	v.attackerModel(doc.AttackerModel)
	v.assetBodies(doc.Assets)
	v.boundaryBodies(doc.TrustBoundaries)
	v.flowBodies(doc.DataFlows)
	v.entryPointBodies(doc.EntryPoints)
	v.decisionBodies(doc.Decisions)
	v.riskBodies(doc.Risks)
	v.controlBodies(doc.Controls)
	v.evidenceBodies(doc.PlannedEvidence)
	v.observationBodies(doc.Observability)
	v.threatBodies(doc.Threats)
	v.criticality(doc.Criticality)
	v.topAbusePaths(doc.TopAbusePaths)
	v.focusPaths(doc.FocusPaths)
	v.supersessions(doc.Supersessions)
	v.analyse(doc)
	v.coverage()
}

func (v *validator) metadata(doc Document) {
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
	if !check.Contains(v.policy.DocumentStatuses, doc.Status) {
		v.Add("status", "unknown document status")
	}
	v.principal("owner", doc.Owner)
	v.RequiredString("summary", doc.Summary)
}

// declareIDs registers and format-checks every declared identifier.
func (v *validator) declareIDs(doc Document) {
	for index, item := range doc.Assumptions {
		v.declare("assumptions", index, item.ID, AssumptionIDPattern, v.assumptions)
	}
	for index, item := range doc.Components {
		v.declare("components", index, item.ID, ComponentIDPattern, v.components)
	}
	for index, item := range doc.Actors {
		v.declare("actors", index, item.ID, ActorIDPattern, v.actors)
	}
	for index, item := range doc.Assets {
		v.declare("assets", index, item.ID, AssetIDPattern, v.assets)
	}
	for index, item := range doc.TrustBoundaries {
		v.declare("trust_boundaries", index, item.ID, BoundaryIDPattern, v.boundaries)
	}
	for index, item := range doc.DataFlows {
		v.declare("data_flows", index, item.ID, FlowIDPattern, v.flows)
	}
	for index, item := range doc.EntryPoints {
		v.declare("entry_points", index, item.ID, EntryPointIDPattern, v.entryPoints)
	}
	for index, item := range doc.Decisions {
		v.declare("decisions", index, item.ID, DecisionIDPattern, v.decisions)
	}
	for index, item := range doc.Risks {
		v.declareRisk(index, item.ID)
	}
	for index, item := range doc.Controls {
		v.declare("controls", index, item.ID, ControlIDPattern, v.controls)
	}
	for index, item := range doc.PlannedEvidence {
		v.declare("planned_evidence", index, item.ID, EvidenceIDPattern, v.evidence)
	}
	for index, item := range doc.Observability {
		v.declare("observability", index, item.ID, ObservationIDPattern, v.observations)
	}
	for index, item := range doc.Threats {
		v.declareThreat(index, item.ID)
	}
}

func (v *validator) declare(
	collection string,
	index int,
	id string,
	pattern *regexp.Regexp,
	set *idSet,
) {
	location := fmt.Sprintf("%s[%d].id", collection, index)
	if !pattern.MatchString(id) {
		v.Addf(location, "expected a stable %s ID", set.noun)
		return
	}
	v.insert(location, id, set)
}

// declareRisk applies the consumer risk pattern rather than a schema-owned
// one: risk IDs come from the project's existing risk register, which this
// tool does not own.
func (v *validator) declareRisk(index int, id string) {
	location := fmt.Sprintf("risks[%d].id", index)
	// Bounds and control-character checks before the consumer pattern; see
	// check.RequiredString for why.
	if !v.RequiredString(location, id) {
		return
	}
	if v.policy.Risk == nil || !v.policy.Risk.MatchString(id) {
		v.Addf(location, "invalid risk %q", id)
		return
	}
	v.insert(location, id, v.risks)
}

func (v *validator) declareThreat(index int, id string) {
	location := fmt.Sprintf("threats[%d].id", index)
	if !ThreatIDPattern.MatchString(id) {
		v.Add(location, "expected a stable threat ID")
		return
	}
	for _, prefix := range reservedIDPrefixes {
		if strings.HasPrefix(id, prefix+"-") {
			v.Addf(location, "threat IDs must not use the reserved %s- prefix", prefix)
			return
		}
	}
	v.insert(location, id, v.threats)
}

func (v *validator) insert(location, id string, set *idSet) {
	if !v.InsertUnique(set.declared, id) {
		v.Addf(location, "duplicate %s ID %q", set.noun, id)
		return
	}
	anchor := strings.ToLower(id)
	if declared, ok := v.allIDs[anchor]; ok {
		if declared == id {
			v.Addf(location, "ID %q is already declared by another collection", id)
		} else {
			v.Addf(location,
				"ID %q differs from %q only by case, and the two share one anchor in the rendered companion",
				id, declared)
		}
		return
	}
	v.allIDs[anchor] = id
}

func (v *validator) requireArray(location string, missing bool) {
	if missing {
		v.Add(location, "expected an array")
	}
}

func (v *validator) scope(scope *Scope) {
	if scope == nil {
		v.Add("scope", "expected an object")
		return
	}
	v.StringList("scope.in_scope", scope.InScope, true)
	v.StringList("scope.out_of_scope", scope.OutOfScope, true)
}

func (v *validator) attackerModel(model *AttackerModel) {
	if model == nil {
		v.Add("attacker_model", "expected an object")
		return
	}
	v.StringList("attacker_model.capabilities", model.Capabilities, true)
	v.StringList("attacker_model.non_capabilities", model.NonCapabilities, true)
}

func (v *validator) assumptionBodies(items []Assumption) {
	for index, item := range items {
		location := fmt.Sprintf("assumptions[%d]", index)
		v.RequiredString(location+".statement", item.Statement)
		v.RequiredString(location+".effect", item.Effect)
	}
}

func (v *validator) componentBodies(items []Component) {
	if len(items) == 0 {
		v.Add("components", "expected a non-empty array")
	}
	for index, item := range items {
		location := fmt.Sprintf("components[%d]", index)
		v.RequiredString(location+".name", item.Name)
		v.RequiredString(location+".zone", item.Zone)
		v.RequiredString(location+".purpose", item.Purpose)
		v.RequiredString(location+".evidence", item.Evidence)
	}
}

func (v *validator) actorBodies(items []Actor) {
	if len(items) == 0 {
		v.Add("actors", "expected a non-empty array")
	}
	for index, item := range items {
		location := fmt.Sprintf("actors[%d]", index)
		v.RequiredString(location+".name", item.Name)
		v.RequiredString(location+".trust", item.Trust)
		v.RequiredString(location+".description", item.Description)
	}
}

func (v *validator) assetBodies(items []Asset) {
	if len(items) == 0 {
		v.Add("assets", "expected a non-empty array")
	}
	for index, item := range items {
		location := fmt.Sprintf("assets[%d]", index)
		v.RequiredString(location+".name", item.Name)
		v.RequiredString(location+".description", item.Description)
		v.RequiredString(location+".objective", item.Objective)
	}
}

func (v *validator) boundaryBodies(items []Boundary) {
	if len(items) == 0 {
		v.Add("trust_boundaries", "expected a non-empty array")
	}
	for index, item := range items {
		location := fmt.Sprintf("trust_boundaries[%d]", index)
		v.RequiredString(location+".name", item.Name)
		v.RequiredString(location+".description", item.Description)
		v.reference(location+".source", item.Source, v.components)
		v.reference(location+".destination", item.Destination, v.components)
		v.StringList(location+".data", item.Data, true)
		v.StringList(location+".channels", item.Channels, true)
		v.StringList(location+".security_guarantees", item.SecurityGuarantees, true)
		v.StringList(location+".validation", item.Validation, true)
		v.RequiredString(location+".implementation_state", item.ImplementationState)
		v.RequiredString(location+".evidence", item.Evidence)
	}
}

func (v *validator) flowBodies(items []DataFlow) {
	if len(items) == 0 {
		v.Add("data_flows", "expected a non-empty array")
	}
	for index, item := range items {
		location := fmt.Sprintf("data_flows[%d]", index)
		v.RequiredString(location+".name", item.Name)
		v.StringList(location+".sequence", item.Sequence, true)
		v.referenceList(location+".boundaries", item.Boundaries, v.boundaries, true)
		v.StringList(location+".data", item.Data, true)
	}
}

func (v *validator) entryPointBodies(items []EntryPoint) {
	if len(items) == 0 {
		v.Add("entry_points", "expected a non-empty array")
	}
	for index, item := range items {
		location := fmt.Sprintf("entry_points[%d]", index)
		v.RequiredString(location+".surface", item.Surface)
		v.RequiredString(location+".reached", item.Reached)
		v.reference(location+".boundary", item.Boundary, v.boundaries)
		v.referenceList(location+".flows", item.Flows, v.flows, true)
		v.RequiredString(location+".notes", item.Notes)
		v.RequiredString(location+".evidence", item.Evidence)
	}
}

func (v *validator) decisionBodies(items []Decision) {
	for index, item := range items {
		location := fmt.Sprintf("decisions[%d]", index)
		v.RequiredString(location+".title", item.Title)
		v.Enum(location+".status", item.Status, decisionStatuses)
		v.referenceTarget(location, item.Reference)
	}
}

func (v *validator) riskBodies(items []Risk) {
	for index, item := range items {
		location := fmt.Sprintf("risks[%d]", index)
		v.RequiredString(location+".title", item.Title)
		v.referenceTarget(location, item.Reference)
	}
}

func (v *validator) controlBodies(items []Control) {
	if len(items) == 0 {
		v.Add("controls", "expected a non-empty array")
	}
	for index, item := range items {
		location := fmt.Sprintf("controls[%d]", index)
		v.RequiredString(location+".title", item.Title)
		v.RequiredString(location+".description", item.Description)
		if !check.Contains(v.policy.ControlStatuses, item.Status) {
			v.Add(location+".status", "unknown control status")
		}
		v.owner(location, item.Owner)
		if v.StringList(location+".requirement_links", item.RequirementLinks, false) {
			for linkIndex, id := range item.RequirementLinks {
				v.requirementLink(
					fmt.Sprintf("%s.requirement_links[%d]", location, linkIndex),
					id,
				)
			}
		}
		v.referenceList(location+".decision_links", item.DecisionLinks, v.decisions, false)
		v.referenceList(location+".risk_links", item.RiskLinks, v.risks, false)
		v.referenceList(location+".evidence_links", item.EvidenceLinks, v.evidence, false)
		// Each category may be empty, but a control that traces to nothing
		// records no obligation and cannot be reviewed.
		if len(item.RequirementLinks)+len(item.DecisionLinks)+
			len(item.RiskLinks)+len(item.EvidenceLinks) == 0 {
			v.Add(location, "expected at least one traceability link")
		}
		v.RequiredString(location+".implementation_note", item.ImplementationNote)
	}
}

func (v *validator) evidenceBodies(items []Evidence) {
	if len(items) == 0 {
		v.Add("planned_evidence", "expected a non-empty array")
	}
	for index, item := range items {
		location := fmt.Sprintf("planned_evidence[%d]", index)
		v.RequiredString(location+".title", item.Title)
		if !check.Contains(v.policy.EvidenceLevels, item.Level) {
			v.Add(location+".level", "unknown evidence level")
		}
		if !check.Contains(v.policy.EvidenceStatuses, item.Status) {
			v.Add(location+".status", "unknown evidence status")
		}
		v.RequiredString(location+".description", item.Description)
		v.owner(location, item.Owner)
		v.referenceList(location+".threat_links", item.ThreatLinks, v.threats, true)
	}
}

func (v *validator) observationBodies(items []Observation) {
	for index, item := range items {
		location := fmt.Sprintf("observability[%d]", index)
		v.RequiredString(location+".surface", item.Surface)
		v.StringList(location+".signals", item.Signals, true)
		v.StringList(location+".redaction", item.Redaction, true)
		v.RequiredString(location+".alert_condition", item.AlertCondition)
		v.referenceList(location+".control_links", item.ControlLinks, v.controls, true)
	}
}

func (v *validator) threatBodies(items []Threat) {
	if len(items) == 0 {
		v.Add("threats", "expected a non-empty array")
	}
	for index, item := range items {
		v.threat(index, item)
	}
}

func (v *validator) threat(index int, item Threat) {
	location := fmt.Sprintf("threats[%d]", index)
	v.RequiredString(location+".title", item.Title)
	v.RequiredString(location+".source", item.Source)
	v.RequiredString(location+".prerequisites", item.Prerequisites)
	v.RequiredString(location+".action", item.Action)
	v.RequiredString(location+".impact", item.Impact)
	v.StringList(location+".abuse_path", item.AbusePath, true)

	v.Enum(location+".likelihood", item.Likelihood, ratingValues)
	v.RequiredString(location+".likelihood_rationale", item.LikelihoodRationale)
	v.Enum(location+".severity", item.Severity, ratingValues)
	v.RequiredString(location+".impact_rationale", item.ImpactRationale)
	v.Enum(location+".priority", item.Priority, priorityValues)

	treatmentKnown := v.Enum(location+".treatment", item.Treatment, treatmentValues)
	v.treatmentRationale(location, item, treatmentKnown)

	v.owner(location, item.Owner)
	v.RequiredString(location+".residual_risk", item.ResidualRisk)
	v.RequiredString(location+".existing_controls", item.ExistingControls)
	v.RequiredString(location+".gaps", item.Gaps)
	v.RequiredString(location+".recommended_mitigations", item.RecommendedMitigations)
	v.RequiredString(location+".detection_ideas", item.DetectionIdeas)

	v.referenceList(location+".actor_links", item.ActorLinks, v.actors, true)
	v.referenceList(location+".asset_links", item.AssetLinks, v.assets, true)
	v.referenceList(location+".boundary_links", item.BoundaryLinks, v.boundaries, true)
	v.referenceList(location+".flow_links", item.FlowLinks, v.flows, false)
	v.referenceList(location+".control_links", item.ControlLinks, v.controls, false)
	v.referenceList(location+".risk_links", item.RiskLinks, v.risks, false)
	v.referenceList(location+".evidence_links", item.EvidenceLinks, v.evidence, false)

	v.treatmentCoupling(location, item, treatmentKnown)
}

// treatmentCoupling enforces that a treatment decision is backed by the
// record that decision implies: choosing to mitigate means naming what will
// do the mitigating; choosing to accept means charging the residual risk to
// the register rather than leaving it unowned.
func (v *validator) treatmentCoupling(location string, item Threat, treatmentKnown bool) {
	if !treatmentKnown {
		return
	}
	switch item.Treatment {
	case "mitigate":
		if len(item.ControlLinks) == 0 {
			v.Add(location+".control_links", "a mitigated threat requires at least one control")
		}
	case "accept":
		if len(item.RiskLinks) == 0 {
			v.Add(location+".risk_links", "an accepted threat requires at least one risk record")
		}
	}
}

func (v *validator) treatmentRationale(location string, item Threat, treatmentKnown bool) {
	rationaleLocation := location + ".treatment_rationale"
	if treatmentKnown && check.Contains(treatmentRationaleRequired, item.Treatment) {
		if !check.Nonempty(item.TreatmentRationale) {
			v.Addf(rationaleLocation, "required for %s", item.Treatment)
			return
		}
	}
	if item.TreatmentRationale != "" {
		v.RequiredString(rationaleLocation, item.TreatmentRationale)
	}
}

func (v *validator) owner(location string, item *Owner) {
	if item == nil {
		v.Add(location+".owner", "expected an object")
		return
	}
	location += ".owner"
	v.principal(location+".principal", item.Principal)
	// Bounds and control-character checks before the consumer pattern; see
	// check.RequiredString for why.
	if v.RequiredString(location+".milestone", item.Milestone) &&
		(v.policy.Milestone == nil || !v.policy.Milestone.MatchString(item.Milestone)) {
		v.Add(location+".milestone", "invalid milestone")
	}
	if item.Issue != nil &&
		v.RequiredString(location+".issue", *item.Issue) &&
		(v.policy.Issue == nil || !v.policy.Issue.MatchString(*item.Issue)) {
		v.Add(location+".issue", "invalid issue reference")
	}
	if !check.Contains(v.policy.Workstreams, item.Workstream) {
		v.Add(location+".workstream", "unknown workstream")
	}
}

// principal validates an accountable principal against the consumer owner
// pattern. Accountability is never optional: an unattributed residual risk
// is one nobody has agreed to carry.
func (v *validator) principal(location, value string) {
	if !v.RequiredString(location, value) {
		return
	}
	if v.policy.Owner == nil || !v.policy.Owner.MatchString(value) {
		v.Addf(location, "invalid principal %q", value)
	}
}

// reference resolves one required local link against its collection.
// Resolution only; coverage accounting happens in analyse.
func (v *validator) reference(location, id string, set *idSet) {
	if !v.RequiredString(location, id) {
		return
	}
	if !check.Contains(set.declared, id) {
		v.Addf(location, "unknown %s %q", set.noun, id)
	}
}

// referenceList resolves a list of local links against its collection.
func (v *validator) referenceList(
	location string,
	ids []string,
	set *idSet,
	requireItems bool,
) {
	if !v.StringList(location, ids, requireItems) {
		return
	}
	for index, id := range ids {
		if !check.Contains(set.declared, id) {
			v.Addf(fmt.Sprintf("%s[%d]", location, index), "unknown %s %q", set.noun, id)
		}
	}
}

func (v *validator) diagrams(items []Diagram) {
	if items == nil {
		v.requireArray("diagrams", true)
		return
	}
	for index, item := range items {
		location := fmt.Sprintf("diagrams[%d]", index)
		v.RequiredString(location+".caption", item.Caption)
		v.referenceTarget(location, item.Reference)
	}
}

// referenceTarget validates a supporting reference: exactly one of a
// repository-relative path or an HTTPS URL on a consumer-allowlisted host.
// The allowlist is what keeps a document author from pointing a governance
// artifact at an arbitrary destination; an empty allowlist means this
// consumer accepts repository-relative references only.
func (v *validator) referenceTarget(location string, ref Reference) {
	switch {
	case ref.Path != "" && ref.URL != "":
		v.Add(location, "expected exactly one of path or url, not both")
	case ref.Path != "":
		if err := check.RepoRelativePath(ref.Path); err != nil {
			v.Add(location+".path", err.Error())
		}
	case ref.URL != "":
		v.referenceURL(location+".url", ref.URL)
	default:
		v.Add(location, "expected exactly one of path or url")
	}
}

func (v *validator) referenceURL(location, value string) {
	if !v.RequiredString(location, value) {
		return
	}
	parsed, err := check.LexicalURI(value)
	if err != nil {
		v.Add(location, err.Error())
		return
	}
	if parsed.Scheme != "https" || !strings.HasPrefix(parsed.Path, "/") {
		v.Add(location, "expected an HTTPS URL with an absolute path")
		return
	}
	if !check.Contains(v.policy.ReferenceHosts, parsed.Host) {
		v.Addf(location, "host %q is not an allowed reference host", parsed.Host)
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

// analyse records what the threats actually reasoned about. This is the
// only place coverage is credited, so a rule can never be satisfied by the
// architecture graph merely referencing its own members.
func (v *validator) analyse(doc Document) {
	for _, threat := range doc.Threats {
		mark(v.assets, threat.AssetLinks)
		mark(v.boundaries, threat.BoundaryLinks)
		mark(v.flows, threat.FlowLinks)
		mark(v.controls, threat.ControlLinks)
		mark(v.risks, threat.RiskLinks)
	}
	// A threat counts as covered when some planned evidence names it.
	for _, item := range doc.PlannedEvidence {
		mark(v.threats, item.ThreatLinks)
	}
	v.analyseEntryPoints(doc)
}

func mark(set *idSet, ids []string) {
	for _, id := range ids {
		if check.Contains(set.declared, id) {
			set.analysed[id] = struct{}{}
		}
	}
}

// analyseEntryPoints credits an entry point using Threat.ReachesEntryPoint,
// the single definition of that predicate.
//
// Threats are indexed by the boundaries they cross first, so only threats
// that could possibly reach an entry point are tested. Scanning every
// threat per entry point would be quadratic, and a crafted document can
// declare far more threats than the identifier space suggests: threat IDs
// take any prefix, so their count is bounded only by the document size
// limit.
func (v *validator) analyseEntryPoints(doc Document) {
	crossing := make(map[string][]Threat, len(doc.TrustBoundaries))
	for _, threat := range doc.Threats {
		for _, boundary := range threat.BoundaryLinks {
			crossing[boundary] = append(crossing[boundary], threat)
		}
	}
	for _, entry := range doc.EntryPoints {
		if !check.Contains(v.entryPoints.declared, entry.ID) {
			continue
		}
		for _, threat := range crossing[entry.Boundary] {
			if threat.ReachesEntryPoint(entry) {
				v.entryPoints.analysed[entry.ID] = struct{}{}
				break
			}
		}
	}
}

func (v *validator) coverage() {
	const unanalysed = "%s %q is declared but never analysed"
	rules := []struct {
		enabled bool
		field   string
		set     *idSet
		// Most rules ask whether a threat analysed this entity. The
		// evidence rule asks the reverse, so it needs its own wording: a
		// threat is analysed by definition — what it can lack is planned
		// evidence naming it.
		message string
	}{
		{v.policy.Coverage.Assets, "assets", v.assets, unanalysed},
		{v.policy.Coverage.Boundaries, "trust_boundaries", v.boundaries, unanalysed},
		{v.policy.Coverage.Flows, "data_flows", v.flows, unanalysed},
		{v.policy.Coverage.EntryPoints, "entry_points", v.entryPoints, unanalysed},
		{v.policy.Coverage.Controls, "controls", v.controls, unanalysed},
		{v.policy.Coverage.Risks, "risks", v.risks, unanalysed},
		{v.policy.Coverage.Evidence, "threats", v.threats, "%s %q has no planned evidence naming it"},
	}
	for _, rule := range rules {
		if !rule.enabled {
			continue
		}
		for _, id := range check.SortedSetDifference(rule.set.declared, rule.set.analysed) {
			v.Addf(rule.field, rule.message, rule.set.noun, id)
		}
	}
}

// criticality validates the priority calibration table. Levels come from
// the schema's own priority vocabulary, so a level outside it is an error
// rather than a project extension; duplicates are rejected because the
// level is the record's key.
func (v *validator) criticality(items []Criticality) {
	levels := make(map[string]struct{}, len(items))
	for index, item := range items {
		location := fmt.Sprintf("criticality[%d]", index)
		if v.Enum(location+".level", item.Level, priorityValues) &&
			!v.InsertUnique(levels, item.Level) {
			v.Addf(location+".level", "duplicate criticality level %q", item.Level)
		}
		v.RequiredString(location+".definition", item.Definition)
		if v.StringList(location+".examples", item.Examples, true) &&
			len(item.Examples) < v.policy.Limits.MinCriticalityExamples {
			v.Addf(
				location+".examples",
				"expected at least %d examples",
				v.policy.Limits.MinCriticalityExamples,
			)
		}
	}
	if !v.policy.Coverage.Criticality {
		return
	}
	// Requiring every level is the consumer's call, so it hangs off the
	// switch rather than off the vocabulary.
	for _, level := range PriorityOrder {
		if !check.Contains(levels, level) {
			v.Addf("criticality", "priority %q has no calibration entry", level)
		}
	}
}

// topAbusePaths validates the curated headline list. It is deliberately not
// derived from priority: "the paths a reader should follow first" is an
// editorial judgement about narrative, and a list that merely repeats every
// critical threat has made no such judgement.
func (v *validator) topAbusePaths(ids []string) {
	if !v.StringList("top_abuse_path_links", ids, false) {
		return
	}
	for index, id := range ids {
		if !check.Contains(v.threats.declared, id) {
			v.Addf(
				fmt.Sprintf("top_abuse_path_links[%d]", index),
				"unknown threat %q", id,
			)
		}
	}
	limits := v.policy.Limits
	if limits.MinTopAbusePaths > 0 && len(ids) < limits.MinTopAbusePaths {
		v.Addf("top_abuse_path_links", "expected at least %d entries", limits.MinTopAbusePaths)
	}
	if limits.MaxTopAbusePaths > 0 && len(ids) > limits.MaxTopAbusePaths {
		v.Addf("top_abuse_path_links", "expected at most %d entries", limits.MaxTopAbusePaths)
	}
}

// focusPaths validates the reviewer's reading list. The path is
// repository-relative and never opened by this tool, exactly like a
// reference path; the threat links are what make an entry worth having, so
// they are required rather than optional.
func (v *validator) focusPaths(items []FocusPath) {
	paths := make(map[string]struct{}, len(items))
	for index, item := range items {
		location := fmt.Sprintf("focus_paths[%d]", index)
		if err := check.RepoRelativePath(item.Path); err != nil {
			v.Add(location+".path", err.Error())
		} else if !v.InsertUnique(paths, item.Path) {
			v.Addf(location+".path", "duplicate focus path %q", item.Path)
		}
		v.RequiredString(location+".why", item.Why)
		v.referenceList(location+".threat_links", item.ThreatLinks, v.threats, true)
	}
}

func (v *validator) supersessions(items []Supersession) {
	v.requireArray("supersessions", items == nil)
	for index, item := range items {
		v.supersession(index, item)
	}
}

func (v *validator) supersession(index int, item Supersession) {
	location := fmt.Sprintf("supersessions[%d]", index)
	if !ThreatIDPattern.MatchString(item.RetiredID) {
		v.Add(location+".retired_id", "invalid threat ID")
	} else if !v.InsertUnique(v.retiredIDs, item.RetiredID) {
		v.Addf(location+".retired_id", "duplicate retired ID %q", item.RetiredID)
	}
	if check.Contains(v.threats.declared, item.RetiredID) {
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
			if !check.Contains(v.threats.declared, replacementID) {
				v.Addf(location+".replacement_ids", "unknown active ID %q", replacementID)
			}
		}
	}
	v.RequiredString(location+".rationale", item.Rationale)
}
